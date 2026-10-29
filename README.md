# Effects of Reasoning Effort and Security Instructions on SQL Injection Resistance in Claude-Generated Python Code

This project examines whether reasoning effort and security instruction specificity affect the proportion of Claude-generated Python programs that function correctly and resist selected SQL injection attacks.

## Methodology

The study will use one Claude model through the API to generate Python code using SQLite. Five database tasks will be evaluated:

- **Product search:** Retrieve matching public products.
- **Customer-order lookup:** Retrieve orders belonging to a specified customer.
- **Record-existence checking:** Return whether a public record matches an input value.
- **Contact updates:** Modify exactly the requested record.
- **Saved search filters:** Store user input and reuse it in a later query.

Each task will be generated at low, medium, and high effort under three prompt conditions: ordinary task instructions, general secure-coding instructions, and specific instructions to prevent SQL injection through parameterized queries.

Five repetitions of each combination will produce **225 programs**. Automated functional and attack tests will evaluate ordinary behavior and selected injection attempts, including filter bypass, UNION-based retrieval, Boolean-based blind injection, and second-order injection.

Results will compare the nine effort–prompt conditions and individual tasks using counts and percentages, with token usage serving as a secondary resource measure. Failed or incomplete programs will not count as successful secure generations, and passing the selected tests will not establish that a program is free of all vulnerabilities.