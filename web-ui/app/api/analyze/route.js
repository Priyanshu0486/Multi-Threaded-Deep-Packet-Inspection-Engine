import { NextResponse } from 'next/server';
import { exec } from 'child_process';
import { promisify } from 'util';
import { writeFile, readFile, unlink, mkdir } from 'fs/promises';
import path from 'path';
import os from 'os';
import crypto from 'crypto';

const execAsync = promisify(exec);

export async function POST(request) {
  let tempInputPath = null;
  let tempOutputPath = null;

  try {
    const formData = await request.formData();
    const file = formData.get('pcap');
    const mode = formData.get('mode');
    const blockType = formData.get('blockType');
    const blockValue = formData.get('blockValue');

    if (!file) {
      return NextResponse.json({ error: 'No PCAP file provided' }, { status: 400 });
    }

    const buffer = Buffer.from(await file.arrayBuffer());
    
    // Create unique temp file paths
    const uuid = crypto.randomUUID();
    const tempDir = os.tmpdir();
    tempInputPath = path.join(tempDir, `input_${uuid}.pcap`);
    tempOutputPath = path.join(tempDir, `output_${uuid}.pcap`);

    await writeFile(tempInputPath, buffer);

    // Build the Java command
    // Note: This assumes the Node.js server is running in a location where it can access the compiled Java classes
    // Or we will run it from the root of the Java project.
    // In our setup, web-ui is inside the root project, so root is `..`
    const isDocker = process.env.IS_DOCKER === 'true';
    const classPath = isDocker ? '/app/target/classes' : path.join(process.cwd(), '..', 'target', 'classes');
    
    let mainClass = 'com.packetanalyzer.dpi.SingleThreadedDpiMain';
    let extraArgs = '';

    if (mode === 'multi') {
      mainClass = 'com.packetanalyzer.dpi.MultiThreadedDpiMain';
      extraArgs = '--lb 2 --fp-per-lb 2';
    }

    let blockArgs = '';
    if (blockType !== 'none' && blockValue) {
      blockArgs = `--block-${blockType} "${blockValue.replace(/"/g, '')}"`;
    }

    const command = `java -cp "${classPath}" ${mainClass} "${tempInputPath}" "${tempOutputPath}" ${extraArgs} ${blockArgs}`;
    
    console.log(`Executing: ${command}`);
    
    const { stdout, stderr } = await execAsync(command);
    console.log("Java Output:", stdout);
    if (stderr) console.error("Java Stderr:", stderr);

    // Parse stdout for stats
    const stats = { total: 0, forwarded: 0, dropped: 0, totalBytes: 0, tcpPackets: 0, udpPackets: 0, activeFlows: 0, workers: { lb: [], fp: [] }, apps: [], domains: [] };
    
    const totalMatch = stdout.match(/Total Packets\s*:\s*(\d+)/i);
    const forwardedMatch = stdout.match(/Forwarded\s*:\s*(\d+)/i);
    const droppedMatch = stdout.match(/Dropped\s*:\s*(\d+)/i);
    const totalBytesMatch = stdout.match(/Total Bytes\s*:\s*(\d+)/i);
    const tcpPacketsMatch = stdout.match(/TCP Packets\s*:\s*(\d+)/i);
    const udpPacketsMatch = stdout.match(/UDP Packets\s*:\s*(\d+)/i);
    const activeFlowsMatch = stdout.match(/Active Flows\s*:\s*(\d+)/i);

    if (totalMatch) stats.total = parseInt(totalMatch[1], 10);
    if (forwardedMatch) stats.forwarded = parseInt(forwardedMatch[1], 10);
    if (droppedMatch) stats.dropped = parseInt(droppedMatch[1], 10);
    if (totalBytesMatch) stats.totalBytes = parseInt(totalBytesMatch[1], 10);
    if (tcpPacketsMatch) stats.tcpPackets = parseInt(tcpPacketsMatch[1], 10);
    if (udpPacketsMatch) stats.udpPackets = parseInt(udpPacketsMatch[1], 10);
    if (activeFlowsMatch) stats.activeFlows = parseInt(activeFlowsMatch[1], 10);

    const lbMatches = [...stdout.matchAll(/LB(\d+)\s*:\s*(\d+)/gi)];
    lbMatches.forEach(m => stats.workers.lb.push({ id: m[1], count: parseInt(m[2], 10) }));
    
    const fpMatches = [...stdout.matchAll(/FP(\d+)\s*:\s*(\d+)/gi)];
    fpMatches.forEach(m => stats.workers.fp.push({ id: m[1], count: parseInt(m[2], 10) }));

    // Parse apps
    const appSectionMatch = stdout.match(/Application Breakdown\s*\n([\s\S]*?)(?:\n\n|\nDetected Domains|\n*$)/);
    if (appSectionMatch && appSectionMatch[1]) {
      const appLines = appSectionMatch[1].trim().split('\n');
      appLines.forEach(line => {
        const parts = line.trim().split(/\s+/);
        if (parts.length >= 2) {
          const count = parseInt(parts[1], 10);
          if (!isNaN(count)) {
            stats.apps.push({ name: parts[0], count: count, percent: parts[2] || '0%' });
          }
        }
      });
    }

    // Parse domains
    const domainSectionMatch = stdout.match(/Detected Domains\s*\n([\s\S]*?)(?:\n\n|\nDropped Packets|\n*$)/);
    if (domainSectionMatch && domainSectionMatch[1]) {
      const domainLines = domainSectionMatch[1].trim().split('\n');
      domainLines.forEach(line => {
        const parts = line.split('->').map(p => p.trim());
        if (parts.length === 2) {
          const domain = parts[0].replace(/^-/, '').trim();
          stats.domains.push({ domain, app: parts[1] });
        }
      });
    }

    // Parse dropped packets list
    stats.droppedList = [];
    const droppedSectionMatch = stdout.match(/Dropped Packets\s*\n([\s\S]*?)(?:\n\n|\n*$)/);
    if (droppedSectionMatch && droppedSectionMatch[1]) {
      const droppedLines = droppedSectionMatch[1].trim().split('\n');
      droppedLines.forEach(line => {
        const p = line.trim();
        if (p.startsWith('-')) {
          stats.droppedList.push(p.replace(/^- /, ''));
        }
      });
    }

    // Move output to public directory for download
    const downloadsDir = path.join(process.cwd(), 'public', 'downloads');
    await mkdir(downloadsDir, { recursive: true }).catch(() => {});
    const publicFileName = `output_${uuid}.pcap`;
    const finalOutputPath = path.join(downloadsDir, publicFileName);
    
    await writeFile(finalOutputPath, await readFile(tempOutputPath));

    // Clean up temp files
    await unlink(tempInputPath).catch(() => {});
    await unlink(tempOutputPath).catch(() => {});

    // Return JSON response
    return NextResponse.json({
      stats,
      downloadUrl: `/downloads/${publicFileName}`
    }, { status: 200 });

  } catch (error) {
    console.error('API Error:', error);
    
    // Attempt cleanup on error
    if (tempInputPath) await unlink(tempInputPath).catch(() => {});
    if (tempOutputPath) await unlink(tempOutputPath).catch(() => {});

    return NextResponse.json({ 
      error: 'Failed to process PCAP', 
      details: error.message 
    }, { status: 500 });
  }
}
