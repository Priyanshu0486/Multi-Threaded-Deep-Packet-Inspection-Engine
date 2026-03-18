# Windows Setup Guide

This guide explains how to build and run the Java version of the DPI Engine on Windows.

The project now uses:

- Java 17+
- Maven 3.8+
- Java source files under `src/main/java`

## Is the project working?

Yes. The Java port was validated locally by:

- compiling all Java sources with `javac`
- running the single-threaded mode against `test_dpi.pcap`
- running the multi-threaded mode against `test_dpi.pcap`
- generating working output PCAP files in both modes

If Maven behaves differently on your machine, that will usually be an environment issue rather than a code issue.

## Option 1: Easiest Setup with Winget

### Step 1: Install Java 17

Open PowerShell and run:

```powershell
winget install EclipseAdoptium.Temurin.17.JDK
```

After installation, close and reopen PowerShell.

Check that Java is available:

```powershell
java -version
javac -version
```

You should see Java 17 or newer.

### Step 2: Install Maven

In PowerShell, run:

```powershell
winget install Apache.Maven
```

Close and reopen PowerShell again, then verify:

```powershell
mvn -version
```

### Step 3: Open the Project

```powershell
cd D:\path\to\packet_analyzer
```

### Step 4: Build the Project

```powershell
mvn compile
```

This should compile the Java code into `target\classes`.

### Step 5: Run the Single-Threaded Version

```powershell
java -cp target\classes com.packetanalyzer.dpi.SingleThreadedDpiMain test_dpi.pcap output_single.pcap
```

### Step 6: Run the Multi-Threaded Version

```powershell
java -cp target\classes com.packetanalyzer.dpi.MultiThreadedDpiMain test_dpi.pcap output_multi.pcap --lb 2 --fp-per-lb 2
```

## Option 2: Install Java and Maven Manually

Use this option if `winget` is unavailable.

### Step 1: Install Java 17

Download and install a JDK 17 distribution such as:

- Eclipse Temurin: https://adoptium.net/
- Oracle JDK: https://www.oracle.com/java/technologies/downloads/

After installing, open PowerShell and verify:

```powershell
java -version
javac -version
```

### Step 2: Install Maven

1. Download Maven from:
   - https://maven.apache.org/download.cgi
2. Extract it to a folder such as:
   - `C:\Tools\apache-maven-3.9.x`
3. Add Maven's `bin` folder to your `Path`

Example:

```text
C:\Tools\apache-maven-3.9.x\bin
```

4. Open a new terminal and verify:

```powershell
mvn -version
```

### Step 3: Build and Run

```powershell
cd D:\path\to\packet_analyzer
mvn compile
java -cp target\classes com.packetanalyzer.dpi.SingleThreadedDpiMain test_dpi.pcap output_single.pcap
```

## Option 3: Using Visual Studio Code

### Step 1: Install VS Code

Download and install:

- https://code.visualstudio.com/

### Step 2: Install Extensions

Install these extensions:

- Extension Pack for Java
- Maven for Java

### Step 3: Open the Project Folder

Open `packet_analyzer` in VS Code.

### Step 4: Ensure Java and Maven Are Installed

In the VS Code terminal, check:

```powershell
java -version
javac -version
mvn -version
```

### Step 5: Build

```powershell
mvn compile
```

### Step 6: Run

Single-threaded:

```powershell
java -cp target\classes com.packetanalyzer.dpi.SingleThreadedDpiMain test_dpi.pcap output_single.pcap
```

Multi-threaded:

```powershell
java -cp target\classes com.packetanalyzer.dpi.MultiThreadedDpiMain test_dpi.pcap output_multi.pcap --lb 2 --fp-per-lb 2
```

## Option 4: Run Without Maven

If Maven is installed incorrectly or blocked by your environment, you can still build the project directly with `javac`.

### Step 1: Create the Output Folder

```powershell
New-Item -ItemType Directory -Force target\classes | Out-Null
```

### Step 2: Compile All Java Files

```powershell
$files = Get-ChildItem src\main\java -Recurse -Filter *.java | ForEach-Object { $_.FullName }
javac -d target\classes $files
```

### Step 3: Run the Program

Single-threaded:

```powershell
java -cp target\classes com.packetanalyzer.dpi.SingleThreadedDpiMain test_dpi.pcap output_single.pcap
```

Multi-threaded:

```powershell
java -cp target\classes com.packetanalyzer.dpi.MultiThreadedDpiMain test_dpi.pcap output_multi.pcap --lb 2 --fp-per-lb 2
```

## Blocking Examples

### Block an application

```powershell
java -cp target\classes com.packetanalyzer.dpi.SingleThreadedDpiMain test_dpi.pcap output_blocked.pcap --block-app YouTube
```

### Block a source IP

```powershell
java -cp target\classes com.packetanalyzer.dpi.MultiThreadedDpiMain test_dpi.pcap output_blocked.pcap --block-ip 192.168.1.50
```

### Block a domain substring

```powershell
java -cp target\classes com.packetanalyzer.dpi.SingleThreadedDpiMain test_dpi.pcap output_blocked.pcap --block-domain facebook
```

## Common Problems

### `java` or `javac` is not recognized

Your JDK is not installed correctly or its `bin` folder is not on `Path`.

Fix:

- reinstall the JDK
- reopen the terminal
- verify with `java -version`

### `mvn` is not recognized

Maven is not installed correctly or not on `Path`.

Fix:

- reinstall Maven
- add Maven `bin` to `Path`
- reopen the terminal

### Maven fails because of repository path issues

This is usually environment-specific.

Fallback:

- use the `javac` build path in Option 4
- confirm the code compiles and runs directly

### Output PCAP is created but packet ordering differs in multi-threaded mode

This is expected. The multi-threaded pipeline focuses on concurrent processing and writing allowed packets, not preserving strict original ordering.

## Recommended Commands

Build with Maven:

```powershell
mvn compile
```

Run single-threaded:

```powershell
java -cp target\classes com.packetanalyzer.dpi.SingleThreadedDpiMain test_dpi.pcap output_single.pcap
```

Run multi-threaded:

```powershell
java -cp target\classes com.packetanalyzer.dpi.MultiThreadedDpiMain test_dpi.pcap output_multi.pcap --lb 2 --fp-per-lb 2
```
