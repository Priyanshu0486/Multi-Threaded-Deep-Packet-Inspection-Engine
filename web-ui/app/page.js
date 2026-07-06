'use client';

import { useState, useRef } from 'react';

export default function Home() {
  const [file, setFile] = useState(null);
  const [mode, setMode] = useState('single');
  const [blockRule, setBlockRule] = useState('domain');
  const [blockValue, setBlockValue] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [results, setResults] = useState(null);
  const fileInputRef = useRef(null);

  const handleFileChange = (e) => {
    if (e.target.files && e.target.files.length > 0) {
      setFile(e.target.files[0]);
    }
  };

  const handleDrop = (e) => {
    e.preventDefault();
    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      setFile(e.dataTransfer.files[0]);
    }
  };

  const handleDragOver = (e) => {
    e.preventDefault();
  };

  const analyzePacket = async (e) => {
    e.preventDefault();
    if (!file) {
      setError('Please upload a PCAP file first.');
      return;
    }

    setLoading(true);
    setError(null);
    setResults(null);

    const formData = new FormData();
    formData.append('pcap', file);
    formData.append('mode', mode);
    formData.append('blockType', blockRule);
    formData.append('blockValue', blockValue);

    try {
      const res = await fetch('/api/analyze', {
        method: 'POST',
        body: formData,
      });

      if (!res.ok) {
        const err = await res.json();
        throw new Error(err.error || 'Failed to analyze PCAP');
      }

      const data = await res.json();
      setResults({
        url: data.downloadUrl,
        stats: data.stats
      });

    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <main className="container">
      <div className="header">
        <h1>Deep Packet Inspection Engine</h1>
        <p>Analyze and filter network traffic by application, domain, or IP.</p>
        
        <div className="glass-panel" style={{ marginTop: '2rem', textAlign: 'left', padding: '1.5rem', background: 'rgba(79, 70, 229, 0.1)', borderColor: 'rgba(79, 70, 229, 0.3)' }}>
          <h3 style={{ color: '#fff', marginBottom: '0.5rem', fontSize: '1.1rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <span>👋</span> About This Project
          </h3>
          <p style={{ color: 'var(--text-main)', fontSize: '0.95rem', lineHeight: '1.6', opacity: 0.9 }}>
            This application is a full-stack wrapper around a custom Java-based <strong>Deep Packet Inspection (DPI)</strong> engine built from scratch. It demonstrates how to parse raw network traffic (Ethernet, IPv4, TCP, UDP), extract five-tuple flow states, and use heuristic analysis on DNS and TLS ClientHello metadata to classify encrypted traffic (like identifying YouTube vs. Netflix). The engine supports both single-threaded debugging and a highly concurrent multi-threaded fast-path architecture.
          </p>
        </div>
      </div>

      <div className="app-grid">
        <div className="glass-panel">
          <h2 style={{ marginBottom: '1.5rem', fontSize: '1.5rem', fontWeight: '600' }}>Configuration</h2>
          <form onSubmit={analyzePacket}>
            
            <div className="form-group">
              <label>PCAP File</label>
              <div 
                className={`file-upload-area ${file ? 'active' : ''}`}
                onDrop={handleDrop}
                onDragOver={handleDragOver}
                onClick={() => fileInputRef.current.click()}
              >
                <input 
                  type="file" 
                  ref={fileInputRef} 
                  accept=".pcap" 
                  onChange={handleFileChange}
                />
                <div className="file-upload-icon">
                  {file ? '📄' : '📁'}
                </div>
                <div className="file-upload-text">
                  {file ? file.name : 'Click or Drag & Drop PCAP'}
                </div>
                {!file && <div className="file-upload-subtext">Supports standard .pcap files</div>}
              </div>
              
              <div style={{ marginTop: '1rem', textAlign: 'center', display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '0.75rem' }}>
                <span style={{ color: 'var(--text-muted)', fontSize: '0.9rem' }}>Don't have a PCAP file?</span>
                <a href="/test_dpi.pcap" download className="btn" style={{ padding: '0.4rem 1rem', fontSize: '0.85rem', width: 'auto', background: 'rgba(79, 70, 229, 0.2)', border: '1px solid rgba(79, 70, 229, 0.5)', color: '#a5b4fc', boxShadow: 'none' }}>
                  Download Sample PCAP
                </a>
              </div>
            </div>

            <div className="form-group">
              <label>Execution Mode</label>
              <select className="form-control" value={mode} onChange={e => setMode(e.target.value)}>
                <option value="single">Single-Threaded (Debug / Serial)</option>
                <option value="multi">Multi-Threaded (High Performance)</option>
              </select>
            </div>

            <div className="form-group">
              <label>Blocking Strategy</label>
              <select className="form-control" value={blockRule} onChange={e => setBlockRule(e.target.value)}>
                <option value="none">No Blocking (Monitor Only)</option>
                <option value="domain">Block by Domain (e.g. youtube.com)</option>
                <option value="app">Block by Application (e.g. YouTube)</option>
                <option value="ip">Block by Source IP</option>
              </select>
            </div>

            {blockRule !== 'none' && (
              <div className="form-group">
                <label>Block Value</label>
                <input 
                  type="text" 
                  className="form-control" 
                  placeholder={`Enter ${blockRule} to block...`}
                  value={blockValue}
                  onChange={e => setBlockValue(e.target.value)}
                  required
                />
              </div>
            )}

            {error && (
              <div className="alert error">
                {error}
              </div>
            )}

            <button type="submit" className="btn" disabled={loading || !file}>
              {loading ? <span className="loading-spinner"></span> : 'Analyze Traffic'}
            </button>
          </form>
        </div>

        <div className="glass-panel" style={{ display: 'flex', flexDirection: 'column' }}>
          <h2 style={{ marginBottom: '1.5rem', fontSize: '1.5rem', fontWeight: '600' }}>Analysis Results</h2>
          
          {!results && !loading && (
            <div style={{ flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'var(--text-muted)' }}>
              Upload a file and run analysis to see results.
            </div>
          )}

          {loading && (
            <div style={{ flex: 1, display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', color: 'var(--primary-color)' }}>
              <div className="loading-spinner" style={{ width: '3rem', height: '3rem', borderWidth: '4px', borderColor: 'rgba(79, 70, 229, 0.3)', borderTopColor: 'var(--primary-color)' }}></div>
              <p style={{ marginTop: '1rem', fontWeight: '500' }}>Processing Packets...</p>
            </div>
          )}

          {results && (
            <>
              <div className="metrics-grid">
                <div className="metric-card">
                  <div className="metric-value">{results.stats.total || 0}</div>
                  <div className="metric-label">Total Packets</div>
                </div>
                <div className="metric-card">
                  <div className="metric-value forwarded">{results.stats.forwarded || 0}</div>
                  <div className="metric-label">Forwarded</div>
                </div>
                <div className="metric-card">
                  <div className="metric-value dropped">{results.stats.dropped || 0}</div>
                  <div className="metric-label">Dropped</div>
                </div>
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(120px, 1fr))', gap: '1rem', marginBottom: '2rem' }}>
                {results.stats.totalBytes !== undefined && !isNaN(results.stats.totalBytes) && (
                  <div style={{ background: 'rgba(0,0,0,0.2)', padding: '1rem', borderRadius: '8px', textAlign: 'center', border: '1px solid rgba(255,255,255,0.05)' }}>
                    <div style={{ fontSize: '1.25rem', fontWeight: 'bold' }}>{(results.stats.totalBytes / 1024).toFixed(1)} KB</div>
                    <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>TOTAL BYTES</div>
                  </div>
                )}
                {results.stats.tcpPackets !== undefined && !isNaN(results.stats.tcpPackets) && (
                  <div style={{ background: 'rgba(0,0,0,0.2)', padding: '1rem', borderRadius: '8px', textAlign: 'center', border: '1px solid rgba(255,255,255,0.05)' }}>
                    <div style={{ fontSize: '1.25rem', fontWeight: 'bold', color: '#60a5fa' }}>{results.stats.tcpPackets}</div>
                    <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>TCP PACKETS</div>
                  </div>
                )}
                {results.stats.udpPackets !== undefined && !isNaN(results.stats.udpPackets) && (
                  <div style={{ background: 'rgba(0,0,0,0.2)', padding: '1rem', borderRadius: '8px', textAlign: 'center', border: '1px solid rgba(255,255,255,0.05)' }}>
                    <div style={{ fontSize: '1.25rem', fontWeight: 'bold', color: '#c084fc' }}>{results.stats.udpPackets}</div>
                    <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>UDP PACKETS</div>
                  </div>
                )}
                {results.stats.activeFlows !== undefined && !isNaN(results.stats.activeFlows) && (
                  <div style={{ background: 'rgba(0,0,0,0.2)', padding: '1rem', borderRadius: '8px', textAlign: 'center', border: '1px solid rgba(255,255,255,0.05)' }}>
                    <div style={{ fontSize: '1.25rem', fontWeight: 'bold', color: '#f472b6' }}>{results.stats.activeFlows}</div>
                    <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>ACTIVE FLOWS</div>
                  </div>
                )}
              </div>

              {results.stats.workers && (results.stats.workers.lb.length > 0 || results.stats.workers.fp.length > 0) && (
                <div style={{ marginBottom: '1.5rem' }}>
                  <h3 style={{ fontSize: '1rem', color: 'var(--text-muted)', marginBottom: '0.5rem', textTransform: 'uppercase', letterSpacing: '0.05em' }}>Worker Distribution</h3>
                  <div style={{ display: 'flex', gap: '1rem' }}>
                    {results.stats.workers.lb.length > 0 && (
                      <div style={{ flex: 1, background: 'rgba(0,0,0,0.2)', borderRadius: '8px', padding: '1rem', border: '1px solid var(--panel-border)' }}>
                        <div style={{ fontSize: '0.85rem', marginBottom: '0.5rem', color: '#9ca3af', fontWeight: '600' }}>Load Balancers</div>
                        {results.stats.workers.lb.map(lb => (
                          <div key={lb.id} style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.9rem', padding: '0.25rem 0' }}>
                            <span>LB-{lb.id}</span>
                            <span style={{ fontWeight: '500', color: 'var(--text-main)' }}>{lb.count}</span>
                          </div>
                        ))}
                      </div>
                    )}
                    {results.stats.workers.fp.length > 0 && (
                      <div style={{ flex: 1, background: 'rgba(0,0,0,0.2)', borderRadius: '8px', padding: '1rem', border: '1px solid var(--panel-border)' }}>
                        <div style={{ fontSize: '0.85rem', marginBottom: '0.5rem', color: '#9ca3af', fontWeight: '600' }}>Fast Path</div>
                        {results.stats.workers.fp.map(fp => (
                          <div key={fp.id} style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.9rem', padding: '0.25rem 0' }}>
                            <span>FP-{fp.id}</span>
                            <span style={{ fontWeight: '500', color: 'var(--text-main)' }}>{fp.count}</span>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                </div>
              )}

              {results.stats.apps && results.stats.apps.length > 0 && (
                <div style={{ marginBottom: '1.5rem' }}>
                  <h3 style={{ fontSize: '1rem', color: 'var(--text-muted)', marginBottom: '0.5rem', textTransform: 'uppercase', letterSpacing: '0.05em' }}>Application Breakdown</h3>
                  <div style={{ background: 'rgba(0,0,0,0.2)', borderRadius: '8px', padding: '1rem', border: '1px solid var(--panel-border)' }}>
                    {results.stats.apps.map((app, idx) => (
                      <div key={idx} style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '0.5rem', fontSize: '0.9rem', borderBottom: '1px solid rgba(255,255,255,0.05)', paddingBottom: '0.5rem' }}>
                        <span style={{ fontWeight: '500', color: '#fff' }}>{app.name}</span>
                        <div style={{ display: 'flex', gap: '1rem', color: 'var(--text-muted)' }}>
                          <span>{app.count} pkts</span>
                          <span style={{ width: '40px', textAlign: 'right', color: 'var(--primary-color)' }}>{app.percent}</span>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {results.stats.domains && results.stats.domains.length > 0 && (
                <div style={{ marginBottom: '1.5rem' }}>
                  <h3 style={{ fontSize: '1rem', color: 'var(--text-muted)', marginBottom: '0.5rem', textTransform: 'uppercase', letterSpacing: '0.05em' }}>Detected Domains</h3>
                  <div style={{ background: 'rgba(0,0,0,0.2)', borderRadius: '8px', padding: '1rem', border: '1px solid var(--panel-border)', maxHeight: '180px', overflowY: 'auto' }}>
                    {results.stats.domains.map((dom, idx) => (
                      <div key={idx} style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '0.5rem', fontSize: '0.9rem' }}>
                        <span style={{ color: '#fff' }}>{dom.domain}</span>
                        <span style={{ color: 'var(--primary-color)', fontWeight: '500' }}>{dom.app}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {results.stats.droppedList && results.stats.droppedList.length > 0 && (
                <div style={{ marginBottom: '1.5rem' }}>
                  <h3 style={{ fontSize: '1rem', color: '#ef4444', marginBottom: '0.5rem', textTransform: 'uppercase', letterSpacing: '0.05em' }}>Dropped Packets History</h3>
                  <div style={{ background: 'rgba(239, 68, 68, 0.1)', borderRadius: '8px', padding: '1rem', border: '1px solid rgba(239, 68, 68, 0.2)', maxHeight: '180px', overflowY: 'auto' }}>
                    {results.stats.droppedList.map((pkt, idx) => (
                      <div key={idx} style={{ marginBottom: '0.5rem', fontSize: '0.85rem', color: '#fca5a5', fontFamily: 'monospace' }}>
                        {pkt}
                      </div>
                    ))}
                  </div>
                </div>
              )}

              <div style={{ marginTop: 'auto', paddingTop: '1rem' }}>
                <a href={results.url} download="filtered_output.pcap" className="btn" style={{ background: 'var(--secondary-color)', boxShadow: '0 4px 14px 0 rgba(16, 185, 129, 0.39)' }}>
                  Download Filtered PCAP
                </a>
              </div>
            </>
          )}
        </div>
      </div>
    </main>
  );
}
