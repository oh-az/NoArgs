# NoArgs: Manipulating and Hiding Process Arguments

<div align="center">
  <img src="https://github.com/oh-az/NoArgs/assets/74332587/fb60d7eb-421f-43c5-9a59-cc489f27872e">
</div>


<p align="center">
  Twitter: <a href="https://x.com/AzizWho">@AzizWho</a>
</p>

## Introduction

NoArgs is a tool designed to dynamically spoof and conceal process arguments while staying undetected. It achieves this by hooking into Windows APIs to dynamically manipulate the Windows internals on the go. This allows NoArgs to alter process arguments discreetly.

## Default Cmd:
![Capture](https://github.com/oh-az/NoArgs/assets/74332587/2cf26a33-af40-40ff-9fa9-6ee823dc1e4d)

### Windows Event Logs:
![Capture4](https://github.com/oh-az/NoArgs/assets/74332587/8fd761e2-f52c-467a-a738-f0eea0cea88c)

## Using NoArgs:
![Capture2](https://github.com/oh-az/NoArgs/assets/74332587/5edb1db8-6951-42fe-b1c8-edf2b8ea4f0e)

### Windows Event Logs:
![Capture3](https://github.com/oh-az/NoArgs/assets/74332587/eb9d8fba-9f0d-4fbf-a022-444e7fda2924)


## Functionality Overview

The tool primarily operates by intercepting process creation calls made by the Windows API function `CreateProcessW`. When a process is initiated, this function is responsible for spawning the new process, along with any specified command-line arguments. The tool intervenes in this process creation flow, ensuring that the arguments are either hidden or manipulated before the new process is launched.

## Hooking Mechanism

Hooking into `CreateProcessW` is achieved through Detours, a popular library for intercepting and redirecting Win32 API functions. Detours allows for the redirection of function calls to custom implementations while preserving the original functionality. By hooking into `CreateProcessW`, the tool is able to intercept the process creation requests and execute its custom logic before allowing the process to be spawned.

## Process Environment Block (PEB) Manipulation

The Process Environment Block **(PEB)** is a data structure utilized by Windows to store information about a process's environment and execution state. The tool leverages the PEB to manipulate the command-line arguments of the newly created processes. By modifying the command-line information stored within the PEB, the tool can alter or conceal the arguments passed to the process.

## Demo: Running Mimikatz and passing it the arguments:

**Process Hacker View:**
![2024-03-15 09-35-11](https://github.com/oh-az/NoArgs/assets/74332587/8d012450-84d5-4cce-81a7-7765a2387812)

### All the arguemnts are hidden dynamically 
**Process Monitor View:**
![2024-03-15 09-38-01](https://github.com/oh-az/NoArgs/assets/74332587/a9409a29-e5e5-4619-bb57-458c6f69c421)

## Technical Implementation

1. **Injection into Command Prompt (cmd):** The tool injects its code into the Command Prompt process, embedding it as Position Independent Code (PIC). This enables seamless integration into cmd's memory space, ensuring covert operation without reliance on specific memory addresses. **(Only for The Obfuscated Executable in the releases page)**

2. **Windows API Hooking:** Detours are utilized to intercept calls to the `CreateProcessW` function. By redirecting the execution flow to a custom implementation, the tool can execute its logic before the original Windows API function.

3. **Custom Process Creation Function:** Upon intercepting a `CreateProcessW` call, the custom function is executed, creating the new process and manipulating its arguments as necessary.

4. **PEB Modification:** Within the custom process creation function, the Process Environment Block (PEB) of the newly created process is accessed and modified to achieve the goal of manipulating or hiding the process arguments.

5. **Execution Redirection:** Upon completion of the manipulations, the execution seamlessly returns to Command Prompt (cmd) without any interruptions. This dynamic redirection ensures that subsequent commands entered undergo manipulation discreetly, evading detection and logging mechanisms that relay on getting the process details from the PEB.

## Installation and Usage:

**Option 1**: Compile NoArgs DLL:

- You will need [Microsoft Detours](https://github.com/microsoft/Detours) installed.

- Compile the DLL.
- Inject the compiled DLL into any cmd instance to manipulate newly created process arguments dynamically.




**Option 2**: Download the precompiled  obfuscated injector (ready-to-go) from the [releases page](https://github.com/oh-az/NoArgs/releases/tag/releases).
