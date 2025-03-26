[![Review Assignment Due Date](https://classroom.github.com/assets/deadline-readme-button-22041afd0340ce965d47ae6ef1cefeee28c7c493a6346c4f15d667ab976d596c.svg)](https://classroom.github.com/a/yoP-3K9_)
# ssh-audit
SSH Connection Tracker

Objective
---------

Write a simple tracker that can audit all ongoing ssh connections to the system at any point in time. 
The tool should provide stats such as:
1. Number of ongoing ssh connections
2. Details of each ssh connection - IP, client port or any other client identifiers
3. Clients that are running multiple ssh connections, if any
4. Duration of each ssh connection

The tool should keep running once initiated and then pump out stats at a configurable time interval.

Nice-to-have stats in real time:
1. SSH connections attempts that were rejected due to authentication failures
2. Any file ops that were attempted by the client and rejected due to permission issues


Repository Setup
----------------

1. Clone the repository
   ```
   git clone <>
   cd ssh-audit
   ```
2. Modify and extend the provided template according to the requirements.
3. Also upload a screen recording and/or detailed screenshots (with captions) of the tool running on your system.

Implementation Details
----------------------

1. Use eBPF to track incoming and ongoing ssh connections.
2. The user-space control program can be implemented using libbpf, BCC or Go eBPF.
3. The time interval should be configurable using command line options.
4. Provide logging for debugging and verification.

Judgement Criteria
------------------

The submission will be judged based on how well the architecture of the eBPF program is built and how optimised it is. The evaluation will be based on the presence of all the mandatory stats followed by nice-to-have stats, documentation and coding standards.

Repository Structure
--------------------

```
/ (Root)
│── README.md          # Detailed assignment instructions
│── Makefile           # Build and run commands
│── src/
│   │── main.c         # User-space control program
│   │── bpf_prog.c     # eBPF program to track ssh connections
│── scripts/
│   │── test.sh        # Script to test the program
|── testing
|   |── README.md      # Details of the implementation, test environment and test cases covered
```

PLEASE NOTE: The repository serves only as a starter template and is flexible to modifications. It could be extended with additional files/folders as appropriate and even based on the library that is chosen for implementation. 
Just ensure the there is a test script and a detailed documentation of what each file does.


Submission Instructions
-----------------------

1. Complete your implementation and ensure it meets the assignment requirements.
2. Update the README.md with detailed instructions on how to build and run your solution.
3. Make a pull request (PR) to submit your final code.
4. Your PR should include:
   - A description of your implementation.
   - Any limitations or known issues.
   - Example test cases


