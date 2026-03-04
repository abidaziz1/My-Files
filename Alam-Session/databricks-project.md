## 🎉 Scenario 2 Complete — 100% Success!

Here's what the run shows:
- ✅ `input_task` — Succeeded in 22s
- ✅ `process_each_file` — Succeeded, **2 scheduled** (ran twice — once per file) in 51s
- ✅ Total duration: 1m 15s
- ✅ Serverless compute — auto terminated after job

---

## 🧠 What Actually Happened — Full Story

### Step by step execution:

**1. You clicked Run Now**
Databricks Workflow engine started the job. No cluster was pre-running — Serverless spun up instantly.

**2. `input_task` ran first (22s)**
Your `02_input_notebook` executed. It created this array:
```python
[
  {"file_name": "raw_data_first"},
  {"file_name": "raw_data_second"}
]
```
Then called `dbutils.jobs.taskValues.set()` to store it as a job-level variable called `my_output`. Think of this like a shared memory slot between tasks.

**3. Workflow engine read the array**
The `processing_task` (For each) picked up `my_output` from `input_task`. It saw 2 items in the array — so it scheduled **2 iterations**.

**4. `process_each_file` ran twice (51s)**
- **Iteration 1**: `{{input.file_name}}` resolved to `raw_data_first` → notebook read `raw_data_first.csv` → wrote output parquet
- **Iteration 2**: `{{input.file_name}}` resolved to `raw_data_second` → notebook read `raw_data_second.csv` → wrote output parquet

**5. Job completed — Succeeded**
Both files processed. Both outputs written to `/Volumes/databricks_rt/rt_schema/orders_volume/output/`

---

## 🗺️ Full Architecture of What We Built

```
Workflow: 02_dynamic_workflow
│
├── Task 1: input_task (Notebook)
│   └── 02_input_notebook
│       ├── Defines array of files
│       └── dbutils.jobs.taskValues.set("my_output", [...])
│                           │
│                           │ passes array down
│                           ▼
└── Task 2: processing_task (For Each)
    ├── Inputs: {{tasks.input_task.values.my_output}}
    ├── Iteration 1: file_name = raw_data_first
    │   └── process_each_file notebook
    │       ├── reads raw_data_first.csv from Volume
    │       └── writes parquet output
    └── Iteration 2: file_name = raw_data_second
        └── process_each_file notebook
            ├── reads raw_data_second.csv from Volume
            └── writes parquet output
```

---

## 🔑 Key Concepts Used

**`dbutils.widgets`** — lets a notebook receive parameters from outside. When the workflow passes `file_name=raw_data_first`, the widget catches it. Without widgets, notebooks can't receive dynamic input.

**`dbutils.jobs.taskValues`** — shared memory between tasks in the same job run. Task 1 sets a value, Task 2 reads it. This is how you pass data between tasks without writing to storage.

**For Each task** — Databricks native loop. Takes an array, spawns one child task execution per item. You control concurrency — run them in parallel or sequentially.

**`{{input.file_name}}`** — the template syntax inside For Each that resolves to each item's value during iteration.

---

## 🎤 Interview Q&A — Dynamic Workflows

---

**Q: How do you build dynamic pipelines in Databricks without hardcoding?**

**A:** I use a combination of `dbutils.widgets` for parameterizing notebooks and `dbutils.jobs.taskValues` for passing data between tasks. In practice I build an input notebook that generates an array of items to process — could be file names, table names, date partitions — and stores it using `taskValues.set()`. Then a For Each task in Databricks Workflows picks up that array and dynamically spawns one execution per item, passing each item's values to a processing notebook via widget parameters. This way the pipeline adapts to however many items exist at runtime with zero code changes.

---

**Q: What is the difference between `dbutils.widgets` and `dbutils.jobs.taskValues`?**

**A:** `dbutils.widgets` is for passing parameters INTO a notebook from outside — from a workflow, another notebook, or manually. It's input-only and scoped to one notebook. `dbutils.jobs.taskValues` is for passing data BETWEEN tasks within the same job run — Task A sets a value, Task B reads it. It's scoped to the job run, not a single notebook. In our pipeline we use both together — `taskValues` passes the file array from the input task to the For Each task, and `widgets` passes each individual file name into the processing notebook.

---

**Q: What is the advantage of For Each task over running multiple hardcoded tasks?**

**A:** With hardcoded tasks you have to know at design time exactly how many items you'll process and create a task for each one. That's not scalable. With For Each, the number of iterations is determined at runtime based on actual data. Today it's 2 files, tomorrow it could be 200 — the workflow handles it automatically. You also control concurrency — run all iterations in parallel for speed, or sequentially if there are dependencies.

---

**Q: How would you scale this in production?**

**A:** In production I would replace the hardcoded array in the input notebook with a dynamic query — for example query a metadata table in Unity Catalog that lists all unprocessed files, or use `dbutils.fs.ls()` to scan a storage path and return all new files since the last run. This way the pipeline is fully autonomous — it discovers what needs to be processed and handles it without manual intervention.

---

## ✅ Scenario 2 Complete!

| What | Why it matters |
|---|---|
| `dbutils.widgets` | Parameterized notebooks — no hardcoding |
| `dbutils.jobs.taskValues` | Task-to-task communication |
| For Each task | Dynamic loops at runtime |
| Serverless compute | Auto spin-up, auto terminate, zero cluster management |

---

Ready for **Scenario 3 — Lakehouse Federation**? This is where we query an external database directly from Databricks without moving any data. Just say **next**!
