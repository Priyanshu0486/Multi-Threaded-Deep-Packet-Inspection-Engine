package com.packetanalyzer.dpi;

import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;

public final class MultiThreadedDpiMain {
    private static final PacketTask POISON = new PacketTask(-1, null);

    private MultiThreadedDpiMain() {
    }

    public static void main(String[] args) throws Exception {
        if (args.length < 2) {
            printUsage();
            return;
        }

        Path input = Path.of(args[0]);
        Path output = Path.of(args[1]);
        Config config = Config.fromArgs(args, 2);
        BlockingRules rules = parseRules(args, 2);
        StatsCollector stats = new StatsCollector();

        System.out.printf("DPI Engine v2.0 (Java, multi-threaded) - LB=%d FP/LB=%d%n",
            config.loadBalancers, config.fastPathsPerLoadBalancer);

        new Engine(config, rules, stats).process(input, output);
    }

    private static BlockingRules parseRules(String[] args, int startIndex) {
        BlockingRules rules = new BlockingRules();
        for (int i = startIndex; i < args.length; i++) {
            switch (args[i]) {
                case "--block-ip" -> {
                    if (i + 1 < args.length) {
                        rules.blockIp(args[++i]);
                    }
                }
                case "--block-app" -> {
                    if (i + 1 < args.length) {
                        rules.blockApp(args[++i]);
                    }
                }
                case "--block-domain" -> {
                    if (i + 1 < args.length) {
                        rules.blockDomain(args[++i]);
                    }
                }
                default -> {
                }
            }
        }
        return rules;
    }

    private static void printUsage() {
        System.out.println("Usage: java ... MultiThreadedDpiMain <input.pcap> <output.pcap> [options]");
        System.out.println("Options:");
        System.out.println("  --lb <count>");
        System.out.println("  --fp-per-lb <count>");
        System.out.println("  --block-ip <ip>");
        System.out.println("  --block-app <app>");
        System.out.println("  --block-domain <domain>");
    }

    private record Config(int loadBalancers, int fastPathsPerLoadBalancer) {
        static Config fromArgs(String[] args, int startIndex) {
            int lbs = 2;
            int fpsPerLb = 2;
            for (int i = startIndex; i < args.length; i++) {
                switch (args[i]) {
                    case "--lb" -> {
                        if (i + 1 < args.length) {
                            lbs = Math.max(1, Integer.parseInt(args[++i]));
                        }
                    }
                    case "--fp-per-lb" -> {
                        if (i + 1 < args.length) {
                            fpsPerLb = Math.max(1, Integer.parseInt(args[++i]));
                        }
                    }
                    default -> {
                    }
                }
            }
            return new Config(lbs, fpsPerLb);
        }
    }

    private static final class Engine {
        private final Config config;
        private final BlockingRules rules;
        private final StatsCollector stats;
        private final List<LoadBalancerWorker> loadBalancers = new ArrayList<>();
        private final List<FastPathWorker> fastPaths = new ArrayList<>();
        private final BlockingQueue<RawPacket> outputQueue = new LinkedBlockingQueue<>();
        private final AtomicBoolean outputDone = new AtomicBoolean(false);

        private Engine(Config config, BlockingRules rules, StatsCollector stats) {
            this.config = config;
            this.rules = rules;
            this.stats = stats;

            int totalFastPaths = config.loadBalancers * config.fastPathsPerLoadBalancer;
            for (int i = 0; i < totalFastPaths; i++) {
                fastPaths.add(new FastPathWorker(i, rules, stats, outputQueue));
            }
            for (int lb = 0; lb < config.loadBalancers; lb++) {
                int start = lb * config.fastPathsPerLoadBalancer;
                List<FastPathWorker> subset = fastPaths.subList(start, start + config.fastPathsPerLoadBalancer);
                loadBalancers.add(new LoadBalancerWorker(lb, subset));
            }
        }

        private void process(Path input, Path output) throws Exception {
            try (PcapReader reader = new PcapReader(input);
                 PcapWriter writer = new PcapWriter(output, reader.globalHeader())) {

                List<Thread> fpThreads = new ArrayList<>();
                for (FastPathWorker fastPath : fastPaths) {
                    Thread thread = new Thread(fastPath, "fast-path-" + fastPath.id);
                    fpThreads.add(thread);
                    thread.start();
                }

                List<Thread> lbThreads = new ArrayList<>();
                for (LoadBalancerWorker loadBalancer : loadBalancers) {
                    Thread thread = new Thread(loadBalancer, "load-balancer-" + loadBalancer.id);
                    lbThreads.add(thread);
                    thread.start();
                }

                Thread outputThread = new Thread(() -> writeOutput(writer), "pcap-output-writer");
                outputThread.start();

                long packetId = 0;
                RawPacket rawPacket;
                while ((rawPacket = reader.readNextPacket()) != null) {
                    Optional<ParsedPacket> parsedOptional = PacketParser.parse(rawPacket);
                    if (parsedOptional.isEmpty()) {
                        continue;
                    }

                    ParsedPacket packet = parsedOptional.get();
                    if (!packet.hasIp() || (!packet.hasTcp() && !packet.hasUdp())) {
                        continue;
                    }

                    stats.recordIngress(packet);
                    PacketTask task = new PacketTask(packetId++, packet);
                    int lbIndex = Math.floorMod(tupleFor(packet).hashCode(), loadBalancers.size());
                    loadBalancers.get(lbIndex).queue.put(task);
                }

                for (LoadBalancerWorker loadBalancer : loadBalancers) {
                    loadBalancer.queue.put(POISON);
                }
                for (Thread lbThread : lbThreads) {
                    lbThread.join();
                }
                for (FastPathWorker fastPath : fastPaths) {
                    fastPath.queue.put(POISON);
                }
                for (Thread fpThread : fpThreads) {
                    fpThread.join();
                }

                outputDone.set(true);
                outputThread.join();
                ConsoleReport.printMultiThreadReport(stats, loadBalancerCounts(), fastPathCounts());
                System.out.println();
                System.out.println("Output written to: " + output.toAbsolutePath());
            } catch (IOException exception) {
                System.err.println("Failed to process PCAP: " + exception.getMessage());
                throw exception;
            }
        }

        private void writeOutput(PcapWriter writer) {
            try {
                while (!outputDone.get() || !outputQueue.isEmpty()) {
                    RawPacket packet = outputQueue.poll(100, TimeUnit.MILLISECONDS);
                    if (packet != null) {
                        writer.writePacket(packet);
                    }
                }
            } catch (InterruptedException exception) {
                Thread.currentThread().interrupt();
            } catch (IOException exception) {
                throw new RuntimeException(exception);
            }
        }

        private long[] loadBalancerCounts() {
            return loadBalancers.stream().mapToLong(worker -> worker.dispatched.get()).toArray();
        }

        private long[] fastPathCounts() {
            return fastPaths.stream().mapToLong(worker -> worker.processed.get()).toArray();
        }
    }

    private static final class LoadBalancerWorker implements Runnable {
        private final int id;
        private final List<FastPathWorker> fastPaths;
        private final BlockingQueue<PacketTask> queue = new ArrayBlockingQueue<>(10000);
        private final AtomicLong dispatched = new AtomicLong();

        private LoadBalancerWorker(int id, List<FastPathWorker> fastPaths) {
            this.id = id;
            this.fastPaths = fastPaths;
        }

        @Override
        public void run() {
            try {
                while (true) {
                    PacketTask task = queue.take();
                    if (task == POISON) {
                        break;
                    }
                    int index = Math.floorMod(tupleFor(task.packet()).hashCode(), fastPaths.size());
                    fastPaths.get(index).queue.put(task);
                    dispatched.incrementAndGet();
                }
            } catch (InterruptedException exception) {
                Thread.currentThread().interrupt();
            }
        }
    }

    private static final class FastPathWorker implements Runnable {
        private final int id;
        private final BlockingRules rules;
        private final StatsCollector stats;
        private final BlockingQueue<RawPacket> outputQueue;
        private final BlockingQueue<PacketTask> queue = new ArrayBlockingQueue<>(10000);
        private final Map<FiveTuple, FlowRecord> flows = new ConcurrentHashMap<>();
        private final AtomicLong processed = new AtomicLong();

        private FastPathWorker(int id, BlockingRules rules, StatsCollector stats, BlockingQueue<RawPacket> outputQueue) {
            this.id = id;
            this.rules = rules;
            this.stats = stats;
            this.outputQueue = outputQueue;
        }

        @Override
        public void run() {
            try {
                while (true) {
                    PacketTask task = queue.take();
                    if (task == POISON) {
                        break;
                    }

                    processed.incrementAndGet();
                    ParsedPacket packet = task.packet();
                    FiveTuple tuple = tupleFor(packet);
                    FlowRecord flow = flows.computeIfAbsent(tuple, FlowRecord::new);
                    flow.incrementPackets();
                    flow.addBytes(packet.rawPacket().data().length);

                    if (!flow.classified()) {
                        ClassificationEngine.classify(packet, flow);
                    }

                    if (!flow.blocked()) {
                        flow.blocked(rules.isBlocked(tuple.srcIp(), flow.appType(), flow.sni()));
                    }

                    stats.recordClassification(flow.appType(), flow.sni());
                    if (flow.blocked()) {
                        stats.recordDropped();
                    } else {
                        stats.recordForwarded();
                        outputQueue.put(packet.rawPacket());
                    }
                }
            } catch (InterruptedException exception) {
                Thread.currentThread().interrupt();
            }
        }
    }

    private static FiveTuple tupleFor(ParsedPacket packet) {
        return new FiveTuple(
            NetUtil.ipToInt(packet.srcIp()),
            NetUtil.ipToInt(packet.dstIp()),
            packet.srcPort(),
            packet.dstPort(),
            packet.protocol()
        );
    }
}
