# Antivirus
Antivirus is a multithreaded desktop application that provides signature-based and heuristic malware scanning. It utilizes the Windows Crypto API for SHA-256 hashing, a Bloom Filter for rapid hash lookups, and an Aho-Corasick trie to detect suspicious API calls and patterns within file contents. Using the Windows Authenticode API, the scanner automatically identifies and bypasses digitally signed binaries from trusted publishers, improving performance.

# Running the Application Directly

If you prefer to use the application without building it from the source code, you can download the pre-compiled binaries directly:

1. Navigate to the **Releases** tab on the GitHub repository page.
2. Download the latest `.zip` file containing the compiled executables (`Antivirus.exe` and `buildDatabase.exe`).
3. Extract the contents to a folder on your Windows machine.
4. If a pre-built threat database is not included, you will need to run `buildDatabase.exe` first to generate the `hash_db` folder from a list of hashes (see the Configuration section below).
5. Double-click `Antivirus.exe` to launch the GUI, select a directory to scan, and click **Scan**.

# Prerequisites for building and compiling

To compile and run this application, a Windows operating system is required, along with the following installed:
- Visual Studio with MSVC compiler (C++17 or later is required)
- Qt Framework (Qt 5 or Qt 6)
- Windows SDK

# Configuration

Before running the main scanner, you must generate the threat database. The application relies on a Bloom filter and a heavily optimized, bucketed binary hash system to verify signatures.

You will need a text file containing known malicious SHA-256 hashes (e.g., `hashes.txt`), formatted with one 64-character hexadecimal string per line. 

Run the database builder utility, which will prompt you for the path to this text file. It will parse the hashes and output a `hash_db` folder containing:
- `bloom_filter.bin`
- Multiple 4-character bucket files (e.g., `0a1b.bin`)

Ensure the `hash_db` folder is located in the parent directory (`..\hash_db\`) relative to where the main Antivirus executable will run, as expected by the scanner.

# Compilation

The project consists of two separate build targets: the database compiler and the main Qt GUI application. 

To compile the database builder via the MSVC Developer Command Prompt:
    cl.exe /std:c++17 /EHsc buildDatabase.cpp /Fe:buildDatabase.exe

To compile the main Antivirus Qt application, navigate to the folder containing your project file (e.g., Antivirus.pro) and run:
    qmake Antivirus.pro
    nmake

Alternatively, you can open the project directly in Qt Creator or Visual Studio using the Qt VS Tools extension and build from the IDE.

# Running the app

First, build the hash database by running the utility and following the prompts:
    .\buildDatabase.exe

Once the database is generated, launch the main antivirus application:
    .\release\Antivirus.exe

From the GUI, use the Browse button to select a target directory, then click Scan to initiate the multithreaded scanning process. The interface will display real-time progress and flag any signature or heuristic detections.
