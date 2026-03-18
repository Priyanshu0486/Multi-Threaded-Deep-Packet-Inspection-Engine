# DPI Engine - Java Packet Analyzer

This project is a Java-based Deep Packet Inspection (DPI) engine that reads packets from a `.pcap` file, classifies traffic, applies filtering rules, and writes the allowed packets to a new `.pcap` file.

It includes:

- a single-threaded mode for learning, debugging, and step-by-step understanding
- a multi-threaded mode that uses load balancers and fast-path workers for higher throughput

## What Is DPI?

Deep Packet Inspection (DPI) is a technique used in networking and cybersecurity to inspect not only packet headers, but also the packet payload to understand what application or service the traffic belongs to.

In a normal packet-forwarding system, devices usually look at Layer 3 and Layer 4 information such as:

- source IP
- destination IP
- source port
- destination port
- protocol

In DPI, we go deeper and inspect application-level data, for example:

- TLS SNI from HTTPS traffic
- HTTP `Host` header from HTTP traffic
- DNS query names from DNS packets

That makes DPI useful for:

- traffic classification
- network monitoring
- parental control and policy enforcement
- security analytics
- malware or suspicious communication detection
- selective blocking of apps, IPs, or domains

Interview-friendly definition:

> Deep Packet Inspection is the process of analyzing packet payloads in addition to headers so that a system can identify applications, domains, or content patterns and then enforce monitoring, classification, or filtering policies.

## What This Project Does

The engine:

- reads packets from a PCAP file without native libraries
- parses Ethernet, IPv4, TCP, and UDP traffic
- identifies flows using a five-tuple
- classifies traffic using TLS SNI, HTTP host, and DNS query extraction
- maps known domains to higher-level applications such as YouTube, Google, Facebook, and GitHub
- blocks traffic based on source IP, application, or domain
- writes non-blocked traffic to a new PCAP file

## Architecture

This repository contains two execution models.

### 1. Single-Threaded Pipeline

Best when you want easy debugging and predictable step-by-step execution.

Flow:

1. Read a packet from the input PCAP.
2. Parse Ethernet, IPv4, TCP, and UDP headers.
3. Build the five-tuple for the flow.
4. Inspect payload data for TLS SNI, HTTP host, or DNS query names.
5. Classify the flow.
6. Apply blocking rules.
7. Write allowed packets to the output PCAP.
8. Print summary statistics.

### 2. Multi-Threaded Pipeline

Best when you want to demonstrate scalable packet processing.

Flow:

1. The reader thread reads packets from the PCAP.
2. Each parsed packet is hashed by five-tuple to a load balancer worker.
3. The load balancer hashes it again into one fast-path worker inside its worker group.
4. The fast-path worker maintains per-flow state in memory.
5. The worker classifies the flow and applies block rules.
6. Allowed packets are pushed to a shared output queue.
7. A writer thread writes those packets to the output PCAP.
8. Final per-worker and overall statistics are printed.

## Internal Design

### Core Components

- `PcapReader`: reads the global header and packet records from the input `.pcap`
- `PacketParser`: parses Ethernet, IPv4, TCP, and UDP fields
- `FiveTuple`: identifies a flow using source IP, destination IP, source port, destination port, and protocol
- `FlowRecord`: stores flow state such as packet count, byte count, classification, SNI/host, and blocked status
- `ClassificationEngine`: classifies traffic using TLS SNI, HTTP host, and DNS query inspection
- `BlockingRules`: decides whether traffic should be dropped based on IP, app, or domain
- `PcapWriter`: writes allowed packets back to a new `.pcap`
- `StatsCollector` and `ConsoleReport`: collect and print processing statistics

### Multi-Threaded Architecture Diagram

```text
Input PCAP
   |
   v
PcapReader
   |
   v
PacketParser
   |
   v
Hash by FiveTuple
   |
   +--> LoadBalancer-0 --> FastPath-0, FastPath-1, ...
   |
   +--> LoadBalancer-1 --> FastPath-2, FastPath-3, ...
   |
   v
FlowRecord + ClassificationEngine + BlockingRules
   |
   +--> Blocked packet -> drop
   |
   +--> Allowed packet -> output queue -> PcapWriter -> Output PCAP
```

### Why Hash by Five-Tuple?

Packets belonging to the same flow should go to the same worker. This is important because:

- flow state stays consistent
- classification can be reused across packets of the same flow
- blocking decisions remain deterministic
- synchronization overhead is reduced

## Traffic Classification Logic

The classification engine uses lightweight heuristics:

- If the packet is TCP on port `443`, it attempts to extract TLS SNI.
- If the packet is TCP on port `80`, it attempts to extract the HTTP `Host` header.
- If the packet uses port `53`, it treats it as DNS and tries to extract the DNS query name.
- If no higher-level identity is found, it falls back to generic app labels such as `HTTP`, `HTTPS`, or `DNS`.

Known applications are inferred from domain patterns. Examples include:

- `youtube`, `youtu.be` -> `YouTube`
- `google`, `gstatic`, `googleapis` -> `Google`
- `facebook`, `fbcdn` -> `Facebook`
- `github`, `githubusercontent` -> `GitHub`

## Blocking Rules

The engine supports three blocking styles:

- `--block-ip <ip>`
- `--block-app <app>`
- `--block-domain <domain>`

Important detail:

- domain blocking is implemented as a case-insensitive substring match against the detected SNI or host value
- that means `--block-domain youtube.com` can block values like `www.youtube.com` if that string is present

## Project Layout

```text
packet_analyzer/
|-- pom.xml
|-- README.md
|-- WINDOWS_SETUP.md
|-- test_dpi.pcap
|-- filtered_multi.pcap
|-- output.pcap
|-- generate_test_pcap.py
`-- src/
    `-- main/
        `-- java/
            `-- com/packetanalyzer/dpi/
                |-- AppType.java
                |-- BlockingRules.java
                |-- ClassificationEngine.java
                |-- ConsoleReport.java
                |-- FiveTuple.java
                |-- FlowRecord.java
                |-- MultiThreadedDpiMain.java
                |-- NetUtil.java
                |-- PacketParser.java
                |-- PacketTask.java
                |-- ParsedPacket.java
                |-- PcapGlobalHeader.java
                |-- PcapPacketHeader.java
                |-- PcapReader.java
                |-- PcapWriter.java
                |-- RawPacket.java
                |-- SingleThreadedDpiMain.java
                |-- SniExtractor.java
                `-- StatsCollector.java
```

## Requirements

- Java 17 or newer
- Maven 3.8 or newer

## Build

```bash
mvn compile
```

This compiles the Java sources into `target/classes`.

## Run From Command Line

### Single-Threaded

```bash
mvn exec:java -Dexec.mainClass=com.packetanalyzer.dpi.SingleThreadedDpiMain -Dexec.args="test_dpi.pcap filtered_single.pcap --block-app YouTube --block-domain facebook.com"
```

### Multi-Threaded

```bash
mvn exec:java -Dexec.mainClass=com.packetanalyzer.dpi.MultiThreadedDpiMain -Dexec.args="test_dpi.pcap filtered_multi.pcap --lb 2 --fp-per-lb 2 --block-domain youtube.com"
```

You can also run compiled classes directly:

```bash
java -cp target/classes com.packetanalyzer.dpi.SingleThreadedDpiMain test_dpi.pcap filtered_single.pcap
java -cp target/classes com.packetanalyzer.dpi.MultiThreadedDpiMain test_dpi.pcap filtered_multi.pcap --lb 2 --fp-per-lb 2 --block-domain youtube.com
```

## IntelliJ IDEA Run Steps

If IntelliJ shows the usage message, that usually means the required program arguments were not provided.

### Run Configuration Setup

1. Open `Run` -> `Edit Configurations...`
2. Select your Java application configuration for `MultiThreadedDpiMain`
3. Set `Main class` to `com.packetanalyzer.dpi.MultiThreadedDpiMain`
4. Set `Use classpath of module` to your project module
5. Set `Working directory` to the project root:

```text
D:\DPI\Packet_analyzer
```

6. In `Program arguments`, enter:

```text
D:\DPI\Packet_analyzer\test_dpi.pcap D:\DPI\Packet_analyzer\output_blocked.pcap --block-domain youtube.com
```

7. Click `Apply`
8. Click `Run`

### Example With More Options

```text
D:\DPI\Packet_analyzer\test_dpi.pcap D:\DPI\Packet_analyzer\output_blocked.pcap --lb 2 --fp-per-lb 2 --block-app YouTube --block-domain youtube.com
```

### Common IntelliJ Errors

- Usage message printed with exit code `0`
  - cause: program arguments were missing
- `FileNotFoundException` with exit code `1`
  - cause: the input `.pcap` path does not exist
- output file created but traffic not blocked as expected
  - cause: the sample packets may not contain the app or domain you are trying to block

## Command-Line Options

Both entry points support:

- `--block-ip <ip>`
- `--block-app <app>`
- `--block-domain <domain>`

The multi-threaded entry point also supports:

- `--lb <count>`
- `--fp-per-lb <count>`

Supported application labels include:

- `HTTP`
- `HTTPS`
- `DNS`
- `Google`
- `YouTube`
- `Facebook`
- `Instagram`
- `WhatsApp`
- `Twitter`
- `Netflix`
- `Amazon`
- `Microsoft`
- `Apple`
- `Telegram`
- `TikTok`
- `Spotify`
- `Zoom`
- `Discord`
- `GitHub`
- `Cloudflare`

## Interview Notes

### How to Explain This Project in an Interview

You can describe it like this:

> I built a Java-based DPI engine that processes offline PCAP traffic, parses packets up to the application-identification level, classifies flows using metadata such as TLS SNI, HTTP host, and DNS query names, and then applies filtering policies in both single-threaded and multi-threaded architectures.

Shorter version:

> It is a packet analysis and filtering engine that uses DPI techniques to identify applications and domains from network traffic and selectively block them.

### Interview Script

#### Explain In 30 Seconds

> I built a Java-based Deep Packet Inspection engine that reads PCAP files, parses network packets, identifies flows using the five-tuple, classifies traffic using TLS SNI, HTTP host, and DNS queries, and applies blocking rules based on IP, app, or domain.

#### Explain In 2 Minutes

> This project is an offline DPI engine written in Java. It reads packets from a PCAP file, parses Ethernet, IPv4, TCP, and UDP headers, and groups packets into flows using the five-tuple. For classification, it inspects application-level metadata such as TLS SNI for HTTPS, HTTP Host headers for HTTP, and DNS query names for DNS traffic. Based on that information, it can infer platforms like YouTube, Google, or Facebook and apply filtering rules. I implemented both a single-threaded version for debugging and correctness and a multi-threaded version with load balancers and fast-path workers to show how packet processing can scale while keeping packets from the same flow on the same worker.

#### Explain In 5 Minutes

> The idea behind the project was to build a simplified DPI engine that demonstrates both networking fundamentals and systems design. The pipeline starts by reading raw packets from a PCAP file and parsing protocol headers. Once a packet is parsed, the engine creates a five-tuple using source IP, destination IP, source port, destination port, and protocol so packets can be associated with the correct flow. Then it performs classification using lightweight DPI heuristics. For HTTPS traffic, it extracts TLS SNI from the ClientHello. For HTTP traffic, it checks the Host header. For DNS, it extracts the query name. Those values are then mapped to higher-level applications such as YouTube, Google, GitHub, or Facebook.
>
> After classification, the engine applies policy rules. It can block traffic by source IP, by application label, or by matching a domain string against the observed SNI or host value. If the packet is allowed, it is written to a new PCAP file. If it is blocked, it is dropped and the statistics are updated.
>
> I implemented two execution models. The single-threaded version is easier to trace and validate. The multi-threaded version is more interesting from a systems perspective because it uses a load-balancing stage and a set of fast-path workers. Packets are hashed by five-tuple so that packets from the same flow consistently reach the same worker, which keeps flow state accurate and reduces synchronization complexity. A separate output writer thread writes allowed packets to the output PCAP. One tradeoff is that original packet ordering is not guaranteed in the multi-threaded path.
>
> From an interview point of view, this project shows understanding of packet parsing, transport and application-layer metadata, concurrency, stateful flow processing, and practical tradeoffs in traffic analysis systems.

### What Makes This Project Strong for Interviews

- demonstrates networking knowledge
- shows understanding of packet structure and protocol parsing
- uses flow-based state management with five-tuples
- includes concurrency and worker partitioning in the multi-threaded version
- has practical filtering logic instead of only theoretical parsing

## Possible Interview Questions

### Conceptual Questions

1. What is Deep Packet Inspection?
   Deep Packet Inspection is the inspection of packet payload and higher-level protocol data in addition to headers, so the system can classify or filter traffic more intelligently.

2. How is DPI different from basic packet filtering?
   Basic filtering mainly uses IPs, ports, and protocols. DPI looks into payload or application-level metadata like SNI, HTTP host, or DNS names.

3. Why is a five-tuple important?
   It uniquely identifies a network flow, allowing packets from the same communication session to share the same state and classification.

4. Why is TLS SNI useful in HTTPS classification?
   Even when payload is encrypted, the TLS ClientHello often exposes the server name indication, which helps identify the requested domain.

5. What is the limitation of using SNI for classification?
   It may be unavailable in some traffic patterns, encrypted in newer protocols or configurations, or insufficient for exact content-level identification.

### Project-Specific Questions

1. How does your project identify YouTube or Google traffic?
   It extracts SNI or host values and maps known domain patterns like `youtube`, `youtu.be`, `google`, or `gstatic` to application labels.

2. How does domain blocking work in your project?
   The project stores blocked domain strings and checks whether the detected SNI or host contains those values using case-insensitive matching.

3. Why did you build both single-threaded and multi-threaded versions?
   The single-threaded version is simpler for debugging and correctness, while the multi-threaded version demonstrates scalability and worker-based packet distribution.

4. How do you preserve flow consistency in the multi-threaded model?
   Packets are hashed by five-tuple so packets from the same flow land on the same worker.

5. Why might output packet order change in the multi-threaded version?
   Because multiple workers process packets concurrently and a separate output thread writes allowed packets from a shared queue.

### Design and Optimization Questions

1. Why use queues between pipeline stages?
   Queues decouple producer and consumer stages, smooth out bursts, and make concurrent processing easier to structure.

2. What data structures are used for concurrency?
   The project uses blocking queues, concurrent hash maps, atomic counters, and worker-local flow maps.

3. What are the limitations of this implementation?
   It focuses on classic PCAP processing, Ethernet/IPv4 traffic, heuristic classification, and offline analysis rather than real-time inline deployment.

4. How would you improve this project further?
   Add IPv6, better TCP stream reassembly, richer protocol parsing, more accurate app signatures, packet ordering guarantees, and live interface capture support.

## Key Limitations

- designed for offline PCAP analysis rather than live inline forwarding
- primarily focused on Ethernet and IPv4 traffic
- classification is heuristic-based, not full content reconstruction
- multi-threaded output does not guarantee original packet order
- encrypted traffic can only be classified using available metadata such as SNI

## Useful Example Commands

```bash
mvn compile
java -cp target/classes com.packetanalyzer.dpi.SingleThreadedDpiMain test_dpi.pcap out_single.pcap --block-domain youtube.com
java -cp target/classes com.packetanalyzer.dpi.MultiThreadedDpiMain test_dpi.pcap out_multi.pcap --lb 4 --fp-per-lb 2 --block-app YouTube
```
