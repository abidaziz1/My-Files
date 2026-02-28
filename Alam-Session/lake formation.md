# AWS LAKE FORMATION: COMPLETE GUIDE

---

## 📚 TABLE OF CONTENTS

1. Introduction to Data Lakes & Lake Formation
2. Lake Formation Architecture & Core Concepts
3. Data Ingestion & Integration
4. Security & Access Control
5. Data Catalog & Metadata Management
6. Query & Analytics Integration
7. Hands-On Labs (Console & CLI)
8. Best Practices & Real-World Use Cases
9. Troubleshooting & Monitoring

---

## 🌊 1. INTRODUCTION TO DATA LAKES & LAKE FORMATION

### What is a Data Lake?

**A Data Lake** is a centralized repository that allows you to store all your structured and unstructured data at any scale.

```
TRADITIONAL DATA WAREHOUSE vs DATA LAKE

Data Warehouse:                Data Lake:
┌─────────────────┐           ┌─────────────────┐
│ Structured Data │           │ All Data Types  │
│ Schema-on-Write │           │ Schema-on-Read  │
│ Expensive       │           │ Cost-Effective  │
│ Limited Scale   │           │ Unlimited Scale │
│ SQL Analytics   │           │ ML, Analytics,  │
│                 │           │ AI, Streaming   │
└─────────────────┘           └─────────────────┘
```

**Data Lake Contents:**
```
┌──────────────────────────────────────────┐
│         DATA LAKE (S3)                   │
├──────────────────────────────────────────┤
│ Structured Data:                         │
│  ├─ CSV, Parquet, ORC                    │
│  ├─ Database exports                     │
│  └─ Transactional data                   │
│                                          │
│ Semi-Structured Data:                    │
│  ├─ JSON, XML                            │
│  ├─ Log files                            │
│  └─ Clickstream data                     │
│                                          │
│ Unstructured Data:                       │
│  ├─ Images, Videos                       │
│  ├─ Documents (PDF, Word)                │
│  ├─ Audio files                          │
│  └─ Social media content                 │
│                                          │
│ Streaming Data:                          │
│  ├─ IoT sensor data                      │
│  ├─ Real-time logs                       │
│  └─ Event streams                        │
└──────────────────────────────────────────┘
```

---

### What is AWS Lake Formation?

**AWS Lake Formation** is a service that makes it easy to set up, secure, and manage a data lake in days instead of months.

**The Problem Lake Formation Solves:**

```
WITHOUT Lake Formation:
┌─────────────────────────────────────────────────┐
│ Manual Steps (Months of Work):                  │
├─────────────────────────────────────────────────┤
│ 1. Create S3 buckets manually                   │
│ 2. Set up complex IAM policies                  │
│ 3. Configure AWS Glue crawlers                  │
│ 4. Build ETL pipelines                          │
│ 5. Implement row/column-level security          │
│ 6. Manage permissions per table                 │
│ 7. Set up audit logging                         │
│ 8. Integrate with analytics tools               │
│ 9. Handle data quality issues                   │
│ 10. Maintain governance policies                │
└─────────────────────────────────────────────────┘
         ↓ TIME: 3-6 MONTHS, Complex Setup

WITH Lake Formation:
┌─────────────────────────────────────────────────┐
│ Automated (Days):                               │
├─────────────────────────────────────────────────┤
│ 1. Point to data sources                        │
│ 2. Lake Formation handles:                      │
│    ├─ S3 bucket setup                           │
│    ├─ IAM policies                              │
│    ├─ Glue cataloging                           │
│    ├─ ETL workflows                             │
│    ├─ Security (row/column level)              │
│    ├─ Centralized permissions                   │
│    └─ Audit logging                             │
│ 3. Start querying immediately                   │
└─────────────────────────────────────────────────┘
         ↓ TIME: DAYS, Automated Setup
```

---

### Key Benefits of Lake Formation

#### 1. **Simplified Data Ingestion**
```
Data Sources → Lake Formation → S3 Data Lake
├─ RDS/Aurora databases
├─ On-premises databases
├─ Third-party apps
├─ S3 buckets
└─ Streaming sources
```

#### 2. **Centralized Security & Governance**
```
Traditional Approach:
├─ S3 bucket policies
├─ IAM policies
├─ Glue resource policies
├─ Athena workgroup policies
└─ Redshift permissions
   (Managed separately - Complex!)

Lake Formation:
└─ Single control plane for ALL permissions
   ├─ Database-level access
   ├─ Table-level access
   ├─ Column-level access (data filtering)
   └─ Row-level access (data filtering)
```

#### 3. **Built-in Data Transformation**
- Automated ETL using AWS Glue
- Data quality checks
- Schema evolution handling
- Deduplication

#### 4. **Fine-Grained Access Control**
```
User: analyst@company.com
├─ Can access: customer_database
│   ├─ Table: orders (all columns)
│   ├─ Table: customers
│   │   ├─ Allowed columns: name, email, city
│   │   ├─ Blocked columns: ssn, credit_card
│   │   └─ Row filter: WHERE region='US-EAST'
│   └─ Table: payments (no access)
```

---

## 🏗️ 2. LAKE FORMATION ARCHITECTURE & CORE CONCEPTS

### High-Level Architecture

```
┌──────────────────────────────────────────────────────────┐
│                    DATA SOURCES                           │
│  ┌──────┐  ┌──────┐  ┌──────┐  ┌──────┐  ┌──────┐      │
│  │ RDS  │  │Aurora│  │ S3   │  │MySQL │  │NoSQL │      │
│  └──┬───┘  └──┬───┘  └──┬───┘  └──┬───┘  └──┬───┘      │
└─────┼─────────┼─────────┼─────────┼─────────┼───────────┘
      └─────────┴─────────┴─────────┴─────────┘
                        ↓
┌──────────────────────────────────────────────────────────┐
│               AWS LAKE FORMATION                          │
│  ┌────────────────────────────────────────────────────┐  │
│  │          DATA INGESTION & ETL                      │  │
│  │  ├─ Blueprints (pre-built workflows)              │  │
│  │  ├─ AWS Glue Integration                          │  │
│  │  └─ Data Quality & Transformation                 │  │
│  └────────────────────────────────────────────────────┘  │
│                        ↓                                  │
│  ┌────────────────────────────────────────────────────┐  │
│  │          DATA CATALOG (AWS Glue)                   │  │
│  │  ├─ Metadata repository                           │  │
│  │  ├─ Schema definitions                            │  │
│  │  └─ Automatic discovery                           │  │
│  └────────────────────────────────────────────────────┘  │
│                        ↓                                  │
│  ┌────────────────────────────────────────────────────┐  │
│  │          SECURITY & GOVERNANCE                     │  │
│  │  ├─ Centralized permissions                       │  │
│  │  ├─ Row/Column-level security                     │  │
│  │  ├─ Data filtering                                │  │
│  │  └─ Audit logging (CloudTrail)                    │  │
│  └────────────────────────────────────────────────────┘  │
│                        ↓                                  │
│  ┌────────────────────────────────────────────────────┐  │
│  │          DATA LAKE STORAGE (S3)                    │  │
│  │  ├─ Raw data                                      │  │
│  │  ├─ Processed data                                │  │
│  │  └─ Curated data                                  │  │
│  └────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────┘
                        ↓
┌──────────────────────────────────────────────────────────┐
│                 ANALYTICS & ML TOOLS                      │
│  ┌────────┐  ┌────────┐  ┌────────┐  ┌────────┐        │
│  │ Athena │  │Redshift│  │EMR     │  │QuickSig│        │
│  │        │  │Spectrum│  │        │  │ht      │        │
│  └────────┘  └────────┘  └────────┘  └────────┘        │
│  ┌────────┐  ┌────────┐                                 │
│  │SageMaker│ │Glue    │                                 │
│  │        │  │DataBrew│                                 │
│  └────────┘  └────────┘                                 │
└──────────────────────────────────────────────────────────┘
```

---

### Core Components

#### 1. **Data Lake Location (S3)**

The foundational storage for your data lake.

```
TYPICAL DATA LAKE STRUCTURE:

s3://my-data-lake/
├── raw/                    ← Landing zone (original data)
│   ├── databases/
│   │   ├── customers/
│   │   ├── orders/
│   │   └── products/
│   ├── logs/
│   └── streams/
│
├── processed/              ← Cleaned & transformed
│   ├── customers/
│   │   └── year=2024/month=01/
│   └── orders/
│
├── curated/                ← Analytics-ready
│   ├── customer_360/
│   ├── sales_summary/
│   └── ml_features/
│
└── archive/                ← Historical data
    └── year=2023/
```

**Lake Formation automatically:**
- Registers S3 locations
- Sets up appropriate IAM policies
- Configures encryption
- Enables versioning

---

#### 2. **AWS Glue Data Catalog**

Central metadata repository for all data lake tables.

```
DATA CATALOG STRUCTURE:

Database: sales_db
├── Table: customers
│   ├── Columns: customer_id, name, email, ssn, address
│   ├── Location: s3://data-lake/curated/customers/
│   ├── Format: Parquet
│   ├── Partition: year, month
│   └── Statistics: row count, size
│
├── Table: orders
│   ├── Columns: order_id, customer_id, amount, order_date
│   ├── Location: s3://data-lake/curated/orders/
│   ├── Format: Parquet
│   └── Partition: year, month, day
│
└── Table: products
    ├── Columns: product_id, name, category, price
    ├── Location: s3://data-lake/curated/products/
    └── Format: Parquet
```

**Metadata includes:**
- Schema (column names, data types)
- Storage location and format
- Partitioning information
- Statistics for query optimization
- Custom properties and tags

---

#### 3. **Blueprints (Pre-built Workflows)**

Templates for common data ingestion patterns.

```
AVAILABLE BLUEPRINTS:

1. Database Snapshot
   ├─ Purpose: One-time load from database
   ├─ Sources: RDS, Aurora, JDBC databases
   └─ Output: Parquet files in S3

2. Incremental Database Load
   ├─ Purpose: Load only new/changed records
   ├─ Method: Bookmarks, timestamps
   └─ Schedule: Hourly, daily, weekly

3. Log File Processing
   ├─ Purpose: Parse and structure logs
   ├─ Formats: Apache, ELB, CloudFront, custom
   └─ Output: Searchable structured data

4. File-based Data Import
   ├─ Purpose: Load CSV, JSON, XML files
   ├─ Features: Schema detection, data validation
   └─ Output: Cataloged, queryable tables
```

---

#### 4. **Permissions Model**

Lake Formation uses a **tag-based access control (LF-TBAC)** model.

```
PERMISSION LEVELS:

Database Level:
└─ DESCRIBE, CREATE_TABLE, ALTER, DROP

Table Level:
├─ SELECT
├─ INSERT
├─ DELETE
├─ ALTER
└─ DROP

Column Level (Data Filtering):
├─ SELECT specific columns only
└─ Exclude sensitive columns (e.g., SSN, credit_card)

Row Level (Data Filtering):
└─ Filter rows based on conditions
    Example: WHERE country='USA' AND dept='Sales'
```

**Grant Example:**
```
Principal: analyst-team
Resource: sales_db.customers table
Permissions:
├─ SELECT on columns: [customer_id, name, email, city]
├─ EXCLUDE columns: [ssn, credit_card, salary]
└─ Row filter: region='US' AND active=true
```

---

#### 5. **LF-Tags (Data Classification)**

Tag-based access control for scalable security.

```
SCENARIO: Healthcare Data Lake

LF-Tags Created:
├─ Sensitivity: [Public, Internal, Confidential, Restricted]
├─ Department: [Finance, HR, Marketing, Engineering]
├─ Compliance: [HIPAA, PCI, GDPR, None]
└─ Environment: [Production, Development, Testing]

Tables Tagged:
├─ patients_table
│   ├─ Sensitivity: Restricted
│   ├─ Compliance: HIPAA
│   └─ Department: Healthcare
│
├─ billing_table
│   ├─ Sensitivity: Confidential
│   ├─ Compliance: PCI, HIPAA
│   └─ Department: Finance
│
└─ public_health_stats
    ├─ Sensitivity: Public
    └─ Compliance: None

Permission Grants:
├─ Data Analysts → Can access: Sensitivity=Public,Internal
├─ Finance Team → Can access: Department=Finance
├─ Compliance Officers → Can access: Compliance=HIPAA,PCI
└─ Doctors → Can access: Sensitivity=Restricted + Dept=Healthcare
```

**Benefits:**
- Scale to thousands of tables without individual grants
- Easy onboarding (grant tags, not individual tables)
- Dynamic permissions (new tables auto-inherit tags)
- Audit-friendly (clear classification)

---

## 📥 3. DATA INGESTION & INTEGRATION

### Ingestion Methods

#### 1. **Blueprints (Recommended for Common Patterns)**

```
WORKFLOW: Database Snapshot Blueprint

Step 1: Select Blueprint
└─ Database snapshot (full load)

Step 2: Configure Source
├─ Source: RDS MySQL database
├─ Connection: my-rds-connection
├─ Database: production_db
├─ Tables: customers, orders, products
└─ Credentials: AWS Secrets Manager

Step 3: Configure Target
├─ Database: analytics_db (in Data Catalog)
├─ S3 Location: s3://my-lake/raw/rds/
├─ Format: Parquet (recommended)
└─ Compression: Snappy

Step 4: Transform Options
├─ Data format conversion: CSV → Parquet
├─ Partition by: year, month
├─ Deduplication: enabled
└─ Data quality checks: enabled

Step 5: Schedule
├─ Frequency: Daily at 2 AM UTC
└─ Workflow name: daily_rds_snapshot

Lake Formation Creates:
├─ Glue crawlers (for schema discovery)
├─ Glue ETL jobs (for transformation)
├─ Glue triggers (for scheduling)
├─ S3 locations (properly configured)
└─ Catalog tables (automatically)
```

---

#### 2. **AWS Glue ETL Jobs**

For custom transformation logic.

```python
# Example: Custom Glue ETL for Lake Formation

import sys
from awsglue.transforms import *
from awsglue.utils import getResolvedOptions
from pyspark.context import SparkContext
from awsglue.context import GlueContext
from awsglue.job import Job
from awsglue.dynamicframe import DynamicFrame

# Initialize
args = getResolvedOptions(sys.argv, ['JOB_NAME'])
sc = SparkContext()
glueContext = GlueContext(sc)
spark = glueContext.spark_session
job = Job(glueContext)
job.init(args['JOB_NAME'], args)

# Read from source (registered in Lake Formation)
source_df = glueContext.create_dynamic_frame.from_catalog(
    database = "raw_db",
    table_name = "raw_customers",
    transformation_ctx = "source_df"
)

# Transform
# 1. Remove duplicates
deduped_df = DeDuplicate.apply(
    frame = source_df,
    keys = ["customer_id"]
)

# 2. Drop sensitive columns
filtered_df = DropFields.apply(
    frame = deduped_df,
    paths = ["ssn", "credit_card"]
)

# 3. Add processing timestamp
from pyspark.sql.functions import current_timestamp
final_df = filtered_df.toDF()
final_df = final_df.withColumn("processed_at", current_timestamp())

# Convert back to DynamicFrame
dynamic_final = DynamicFrame.fromDF(final_df, glueContext, "dynamic_final")

# Write to Lake Formation managed location
glueContext.write_dynamic_frame.from_catalog(
    frame = dynamic_final,
    database = "curated_db",
    table_name = "customers",
    transformation_ctx = "write_df"
)

job.commit()
```

---

#### 3. **Direct S3 Upload with Registration**

```bash
# Upload data to S3
aws s3 cp local_data.csv s3://my-data-lake/raw/customers/

# Register location with Lake Formation
aws lakeformation register-resource \
  --resource-arn arn:aws:s3:::my-data-lake/raw/customers \
  --use-service-linked-role

# Create Glue crawler to catalog the data
aws glue create-crawler \
  --name customers-crawler \
  --role AWSGlueServiceRole-LakeFormation \
  --database-name raw_db \
  --targets '{
    "S3Targets": [
      {"Path": "s3://my-data-lake/raw/customers/"}
    ],
    "CatalogTargets": []
  }' \
  --lake-formation-configuration '{
    "UseLakeFormationCredentials": true
  }'

# Run crawler
aws glue start-crawler --name customers-crawler
```

---

#### 4. **Streaming Ingestion (Kinesis)**

```
Real-time Data Pipeline:

IoT Devices / Applications
        ↓
Kinesis Data Streams
        ↓
Kinesis Data Firehose
├─ Transform: Lambda (optional)
├─ Buffer: 1 MB or 60 seconds
└─ Deliver to: s3://lake/streaming/
        ↓
Lake Formation
├─ Auto-catalog with Glue crawler
└─ Apply permissions
        ↓
Query with Athena (near real-time)
```

**Firehose Configuration:**
```json
{
  "DeliveryStreamName": "iot-to-lake",
  "S3DestinationConfiguration": {
    "RoleARN": "arn:aws:iam::123456789012:role/firehose-role",
    "BucketARN": "arn:aws:s3:::my-data-lake",
    "Prefix": "streaming/iot/year=!{timestamp:yyyy}/month=!{timestamp:MM}/day=!{timestamp:dd}/",
    "BufferingHints": {
      "SizeInMBs": 5,
      "IntervalInSeconds": 300
    },
    "CompressionFormat": "GZIP",
    "DataFormatConversionConfiguration": {
      "Enabled": true,
      "OutputFormatConfiguration": {
        "Serializer": {
          "ParquetSerDe": {}
        }
      },
      "SchemaConfiguration": {
        "DatabaseName": "streaming_db",
        "TableName": "iot_events",
        "Region": "us-east-1",
        "RoleARN": "arn:aws:iam::123456789012:role/firehose-role"
      }
    }
  }
}
```

---

### Data Formats & Optimization

#### Recommended Formats

```
FORMAT COMPARISON:

CSV/JSON (Text):
├─ Pros: Human-readable, universal
├─ Cons: Large size, slow queries
├─ Compression: GZIP (3-5x reduction)
└─ Use case: Raw landing zone

Parquet (Columnar):
├─ Pros: Fast queries, small size, schema embedded
├─ Cons: Not human-readable
├─ Compression: Snappy (10x smaller than CSV)
├─ Best for: Analytics, ML features
└─ ✅ RECOMMENDED for Lake Formation

ORC (Columnar):
├─ Pros: Very compact, fast
├─ Cons: Less tool support than Parquet
└─ Use case: Hadoop/Hive workloads

Avro (Row):
├─ Pros: Schema evolution, streaming
├─ Cons: Larger than Parquet
└─ Use case: Event streams, CDC
```

**Performance Example:**
```
Same dataset (1 million rows):

CSV (gzipped):     500 MB
JSON (gzipped):    800 MB
Parquet (snappy):  50 MB  ← 10x smaller!
ORC (snappy):      45 MB

Query Performance (Athena):
CSV:      45 seconds, $0.50
Parquet:  3 seconds,  $0.05  ← 15x faster, 10x cheaper!
```

---

#### Partitioning Strategy

```
EFFECTIVE PARTITIONING:

sales_data table:
s3://lake/curated/sales/
├── year=2024/
│   ├── month=01/
│   │   ├── day=01/
│   │   │   └── data.parquet
│   │   ├── day=02/
│   │   └── day=03/
│   └── month=02/
└── year=2023/

Query optimization:
SELECT * FROM sales 
WHERE year='2024' AND month='01'
→ Scans only: s3://lake/curated/sales/year=2024/month=01/
→ Skips: 99% of data!
```

**Partitioning Best Practices:**
- ✅ Partition by frequently filtered columns (date, region, category)
- ✅ Create balanced partitions (10MB - 1GB per partition)
- ❌ Avoid too many partitions (>10,000 slows queries)
- ❌ Don't partition by high-cardinality columns (user_id, transaction_id)

---

## 🔐 4. SECURITY & ACCESS CONTROL

### Permission Model Deep Dive

#### Traditional AWS vs Lake Formation

```
TRADITIONAL AWS IAM:

Grant S3 access:
{
  "Effect": "Allow",
  "Action": ["s3:GetObject"],
  "Resource": "arn:aws:s3:::my-bucket/customers/*"
}

Grant Glue access:
{
  "Effect": "Allow",
  "Action": ["glue:GetTable", "glue:GetDatabase"],
  "Resource": "*"
}

Grant Athena access:
{
  "Effect": "Allow",
  "Action": ["athena:StartQueryExecution"],
  "Resource": "*"
}

Result: User can access ALL data in bucket
Problem: No column/row-level security!
```

```
LAKE FORMATION:

Single permission grant:
Principal: data-analyst
Database: customer_db
Table: customers
Permissions:
├─ SELECT on columns: [id, name, email, city]
├─ EXCLUDE columns: [ssn, salary, credit_card]
└─ Row filter: WHERE region='US-EAST'

Lake Formation automatically:
├─ Creates necessary IAM policies
├─ Configures S3 bucket policies
├─ Sets up Glue catalog permissions
├─ Applies cell-level filtering
└─ Enables audit logging

Result: User sees ONLY filtered data across ALL tools
        (Athena, Redshift Spectrum, EMR, QuickSight)
```

---

### Row-Level Security (Data Filtering)

```sql
-- Create data filter expression

SCENARIO: Regional Sales Analysts

Table: sales_transactions
├─ Columns: transaction_id, amount, customer_id, region, date
└─ Rows: 10 million records across all regions

Grant to: east-coast-analysts
Filter Expression:
  region IN ('US-EAST', 'US-NORTHEAST')

Grant to: west-coast-analysts  
Filter Expression:
  region IN ('US-WEST', 'US-SOUTHWEST')

Grant to: managers
Filter Expression:
  (No filter - see all regions)
```

**What analysts see:**

```sql
-- East Coast Analyst runs:
SELECT * FROM sales_transactions;

-- Lake Formation automatically rewrites to:
SELECT * FROM sales_transactions 
WHERE region IN ('US-EAST', 'US-NORTHEAST');

-- Analyst doesn't even know filter exists!
```

**Complex Filter Example:**
```sql
-- Healthcare scenario: Doctors see only their patients

Filter Expression:
doctor_id = (
  SELECT employee_id 
  FROM employees 
  WHERE email = '${aws:userid}@hospital.com'
)
AND 
patient_status = 'active'
AND
consent_given = true
```

---

### Column-Level Security

```
TABLE: employees
┌──────────┬────────┬────────┬──────┬────────────┬────────┐
│ emp_id   │ name   │ email  │ ssn  │ salary     │ dept   │
└──────────┴────────┴────────┴──────┴────────────┴────────┘

Permission Grants:

1. HR Department:
   ├─ Columns: ALL
   └─ Row filter: None
   
   Sees:
   ┌──────────┬────────┬────────┬──────┬────────────┬────────┐
   │ emp_id   │ name   │ email  │ ssn  │ salary     │ dept   │
   └──────────┴────────┴────────┴──────┴────────────┴────────┘

2. Managers:
   ├─ Columns: [emp_id, name, email, dept]
   ├─ Exclude: [ssn, salary]
   └─ Row filter: dept = 'Engineering'
   
   Sees:
   ┌──────────┬────────┬────────┬────────┐
   │ emp_id   │ name   │ email  │ dept   │
   └──────────┴────────┴────────┴────────┘
   (Only Engineering employees)

3. Peer Employees:
   ├─ Columns: [emp_id, name, email, dept]
   ├─ Exclude: [ssn, salary]
   └─ Row filter: emp_id = current_user
   
   Sees:
   ┌──────────┬────────┬────────┬────────┐
   │ emp_id   │ name   │ email  │ dept   │
   └──────────┴────────┴────────┴────────┘
   (Only their own record)
```

---

### LF-Tags Based Access Control (LF-TBAC)

**Traditional Grants (Doesn't Scale):**
```
100 analysts × 500 tables = 50,000 individual grants!
↓
Unmanageable, error-prone, slow
```

**LF-Tags Approach (Scales):**
```
STEP 1: Define LF-Tags
├─ Classification: [Public, Internal, Confidential, Restricted]
├─ Department: [Sales, Marketing, Engineering, Finance]
└─ Region: [US, EU, APAC, Global]

STEP 2: Tag Tables
├─ customer_data
│   ├─ Classification: Confidential
│   ├─ Department: Sales
│   └─ Region: Global
│
├─ financial_reports
│   ├─ Classification: Restricted
│   ├─ Department: Finance
│   └─ Region: US
│
└─ public_datasets
    ├─ Classification: Public
    └─ Region: Global

STEP 3: Grant Based on Tags (Not individual tables!)
├─ Sales Team → Classification IN (Public, Internal, Confidential)
│              AND Department = Sales
│
├─ Finance Team → Classification IN (Confidential, Restricted)
│                AND Department = Finance
│
└─ Data Scientists → Classification IN (Public, Internal)
                    AND Region = Global

Result: 
├─ 100 analysts managed with 3 tag-based grants
├─ New tables automatically inherit permissions
└─ Easy to audit and modify
```

---

### Cross-Account Access

```
SCENARIO: Share data lake with partner account

Account A (Data Lake Owner):     Account B (Consumer):
┌──────────────────────────┐    ┌──────────────────────┐
│ Lake Formation           │    │                      │
│ ├─ Database: shared_db   │    │  Analysts query via: │
│ ├─ Table: customer_data  │◄───┤  ├─ Athena           │
│ └─ Table: sales_data     │    │  ├─ Redshift Spectrum│
└──────────────────────────┘    │  └─ EMR              │
                                └──────────────────────┘

Setup Steps:

1. Account A: Create Resource Share (AWS RAM)
   ├─ Share: shared_db database
   ├─ With: Account B (123456789012)
   └─ Permissions: SELECT on all tables

2. Account A: Grant Lake Formation Permissions
   ├─ Principal: Account B
   ├─ Resource: shared_db.customer_data
   ├─ Permissions: SELECT
   └─ Column filter: Exclude [ssn, credit_card]

3. Account B: Accept Resource Share
   └─ Database appears in Glue Catalog

4. Account B: Query Shared Data
   SELECT * FROM shared_db.customer_data
   └─ Sees filtered data (no SSN, no credit cards)
```

---

## 📊 5. DATA CATALOG & METADATA MANAGEMENT

### Glue Data Catalog Structure

```
DATA CATALOG HIERARCHY:

Account
└─ Region (e.g., us-east-1)
    └─ Catalogs
        └─ Databases
            └─ Tables
                └─ Partitions (optional)
                    └─ Columns

Example:
├─ Database: ecommerce_db
│   ├─ Table: customers
│   │   ├─ Column: customer_id (bigint)
│   │   ├─ Column: name (string)
│   │   ├─ Column: email (string)
│   │   └─ Location: s3://lake/customers/
│   │
│   ├─ Table: orders
│   │   ├─ Column: order_id (bigint)
│   │   ├─ Column: customer_id (bigint)
│   │   ├─ Column: amount (decimal)
│   │   ├─ Partition: year (int)
│   │   ├─ Partition: month (int)
│   │   └─ Location: s3://lake/orders/
│   │
│   └─ Table: products
│       └─ Location: s3://lake/products/
│
└─ Database: analytics_db
    └─ Table: customer_360
        └─ Location: s3://lake/curated/customer_360/
```

---

### Automated Schema Discovery (Crawlers)

```
AWS GLUE CRAWLER:

Configuration:
├─ Name: ecommerce-crawler
├─ Data source: s3://my-lake/raw/
├─ IAM role: AWSGlueServiceRole-LakeFormation
├─ Target database: ecommerce_db
├─ Schedule: Daily at 6 AM UTC
└─ Configuration:
    ├─ Create partitions: Yes
    ├─ Update schema: Yes
    ├─ Delete old tables: No
    └─ Grouping: Infer schema from first 2 files

Crawler Process:
1. Scan S3 location
2. Sample files to infer schema
3. Detect format (CSV, Parquet, JSON)
4. Identify partitions
5. Create/update tables in catalog
6. Add metadata (row count, size, etc.)

Result:
├─ Table: customers
│   ├─ Detected columns with data types
│   ├─ S3 location registered
│   ├─ Format: Parquet
│   └─ Classification: parquet
│
└─ Table: orders
    ├─ Detected partitions: year, month
    ├─ S3 location registered
    └─ Format: CSV
```

---

### Schema Evolution

```
SCENARIO: Adding new column to existing table

Day 1: customers table
┌────────────┬────────┬────────────┐
│customer_id │ name   │ email      │
└────────────┴────────┴────────────┘

Day 30: New column added to source
┌────────────┬────────┬────────────┬────────┐
│customer_id │ name   │ email      │ phone  │
└────────────┴────────┴────────────┴────────┘

Glue Crawler detects change:
├─ Schema version 1: 3 columns
├─ Schema version 2: 4 columns (phone added)
└─ Action: Update table schema, mark as version 2

Queries:
├─ Old data (no phone column): Returns NULL for phone
├─ New data (with phone): Returns actual phone value
└─ Backwards compatible!
```

**Schema Evolution Modes:**
```
1. Add columns: ✅ Fully supported (backwards compatible)
2. Remove columns: ⚠️ Supported (handle with care)
3. Change data type: ❌ Not recommended (create new column)
4. Rename column: ❌ Treated as remove + add (data loss)
```

---

### Metadata Best Practices

#### 1. **Table Properties**

```python
# Add custom metadata to tables

table_input = {
    'Name': 'customers',
    'StorageDescriptor': {...},
    'Parameters': {
        'classification': 'parquet',
        'compressionType': 'snappy',
        'owner': 'data-eng-team',
        'pii': 'true',
        'retention_days': '730',
        'source_system': 'salesforce',
        'update_frequency': 'daily',
        'data_quality_score': '95'
    }
}
```

#### 2. **Partitioning Metadata**

```
PARTITION PROJECTION (Performance Optimization):

Without projection:
├─ Athena calls Glue to list partitions
├─ Slow for tables with 100,000+ partitions
└─ Extra API costs

With projection:
├─ Athena generates partition paths automatically
├─ No Glue API calls needed
└─ Much faster queries!

Configuration:
'Parameters': {
    'projection.enabled': 'true',
    'projection.year.type': 'integer',
    'projection.year.range': '2020,2030',
    'projection.month.type': 'integer',
    'projection.month.range': '1,12',
    'projection.day.type': 'integer',
    'projection.day.range': '1,31',
    'storage.location.template': 
        's3://lake/data/year=${year}/month=${month}/day=${day}/'
}
```

---

## 🔍 6. QUERY & ANALYTICS INTEGRATION

### Supported Analytics Services

```
┌─────────────────────────────────────────────────┐
│         LAKE FORMATION DATA LAKE                 │
│              (S3 + Glue Catalog)                 │
└────────────┬────────────────────────────────────┘
             │
    ┌────────┼────────┬────────────┬──────────────┐
    │        │        │            │              │
┌───▼──┐ ┌──▼───┐ ┌──▼────┐ ┌─────▼────┐ ┌──────▼─────┐
│Athena│ │Redsh-│ │ EMR   │ │SageMaker │ │ QuickSight │
│      │ │ift   │ │       │ │          │ │            │
│SQL   │ │Spec- │ │Spark/ │ │ML/AI     │ │ BI         │
│Query │ │trum  │ │Hadoop │ │          │ │Dashboards  │
└──────┘ └──────┘ └───────┘ └──────────┘ └────────────┘
```

---

### 1. **Amazon Athena**

**Purpose:** Serverless SQL queries directly on S3 data

```sql
-- Query Lake Formation table with Athena

-- Setup (one-time)
CREATE EXTERNAL TABLE IF NOT EXISTS sales_db.transactions (
    transaction_id BIGINT,
    customer_id BIGINT,
    amount DECIMAL(10,2),
    product_id INT,
    transaction_date DATE
)
PARTITIONED BY (year INT, month INT)
STORED AS PARQUET
LOCATION 's3://my-lake/curated/transactions/'
TBLPROPERTIES ('parquet.compression'='SNAPPY');

-- Athena automatically respects Lake Formation permissions!

-- Example queries:

-- 1. Daily sales summary
SELECT 
    transaction_date,
    COUNT(*) as num_transactions,
    SUM(amount) as total_sales,
    AVG(amount) as avg_transaction
FROM sales_db.transactions
WHERE year = 2024 AND month = 1
GROUP BY transaction_date
ORDER BY transaction_date DESC;

-- 2. Top customers (with column filtering applied)
SELECT 
    c.customer_id,
    c.name,          -- ✅ Allowed
    -- c.ssn,        -- ❌ Blocked by Lake Formation
    COUNT(t.transaction_id) as num_orders,
    SUM(t.amount) as total_spent
FROM sales_db.customers c
JOIN sales_db.transactions t ON c.customer_id = t.customer_id
WHERE t.year = 2024
GROUP BY c.customer_id, c.name
ORDER BY total_spent DESC
LIMIT 10;

-- 3. Regional analysis (with row filtering)
-- User from US-EAST region sees ONLY US-EAST data
SELECT 
    region,
    COUNT(*) as sales_count
FROM sales_db.transactions
-- Lake Formation adds: WHERE region = 'US-EAST'
GROUP BY region;
```

**Athena Performance Tips:**
```sql
-- 1. Use partitioning
SELECT * FROM sales
WHERE year=2024 AND month=1  -- ✅ Fast (partition pruning)
-- vs
SELECT * FROM sales
WHERE transaction_date >= '2024-01-01'  -- ❌ Slow (full scan)

-- 2. Use columnar formats
Parquet/ORC: 10x faster than CSV

-- 3. Compress data
Snappy compression: 5x smaller, minimal CPU overhead

-- 4. Use CTAS for complex queries
CREATE TABLE sales_summary AS
SELECT year, month, SUM(amount) as total
FROM sales
GROUP BY year, month;
```

---

### 2. **Amazon Redshift Spectrum**

**Purpose:** Query S3 data from Redshift data warehouse

```sql
-- Connect Redshift to Lake Formation

-- Step 1: Create external schema (points to Glue catalog)
CREATE EXTERNAL SCHEMA lake_schema
FROM DATA CATALOG
DATABASE 'sales_db'
IAM_ROLE 'arn:aws:iam::123456789012:role/RedshiftSpectrumRole'
REGION 'us-east-1';

-- Step 2: Query external tables alongside Redshift tables
SELECT 
    -- From Redshift table (fast, local)
    dw.customer_segment,
    dw.lifetime_value,
    -- From Lake Formation table (external, S3)
    ext.transaction_date,
    ext.amount
FROM 
    dwh_schema.customer_dim dw  -- Redshift table
JOIN 
    lake_schema.transactions ext  -- Lake Formation table
    ON dw.customer_id = ext.customer_id
WHERE 
    ext.year = 2024
    AND dw.customer_segment = 'Premium';

-- Hybrid architecture benefits:
-- ├─ Hot data in Redshift (fast, expensive)
-- ├─ Cold data in Lake Formation (slower, cheap)
-- └─ Query both seamlessly!
```

---

### 3. **Amazon EMR (Big Data Processing)**

```python
# PySpark on EMR accessing Lake Formation

from pyspark.sql import SparkSession

# Create Spark session with Lake Formation integration
spark = SparkSession.builder \
    .appName("LakeFormation-EMR") \
    .config("hive.metastore.client.factory.class", 
            "com.amazonaws.glue.catalog.metastore.AWSGlueDataCatalogHiveClientFactory") \
    .enableHiveSupport() \
    .getOrCreate()

# Read from Lake Formation table
customers_df = spark.sql("""
    SELECT * FROM sales_db.customers
    WHERE country = 'USA'
""")

transactions_df = spark.sql("""
    SELECT * FROM sales_db.transactions
    WHERE year = 2024
""")

# Complex processing
customer_insights = customers_df.join(
    transactions_df, 
    "customer_id"
).groupBy("customer_segment").agg(
    {"amount": "sum", "transaction_id": "count"}
)

# Write back to Lake Formation
customer_insights.write \
    .mode("overwrite") \
    .format("parquet") \
    .partitionBy("year", "month") \
    .save("s3://my-lake/curated/customer_insights/")

# Register with catalog
spark.sql("""
    CREATE EXTERNAL TABLE IF NOT EXISTS analytics_db.customer_insights
    STORED AS PARQUET
    LOCATION 's3://my-lake/curated/customer_insights/'
""")
```

---

### 4. **Amazon SageMaker (ML)**

```python
# Use Lake Formation data for ML training

import boto3
import sagemaker
from sagemaker import get_execution_role

# Query Lake Formation with Athena
athena_client = boto3.client('athena')

query = """
SELECT 
    customer_age,
    customer_income,
    num_past_purchases,
    avg_purchase_amount,
    churned
FROM ml_features_db.customer_churn_features
WHERE training_set = TRUE
"""

# Execute query
response = athena_client.start_query_execution(
    QueryString=query,
    QueryExecutionContext={'Database': 'ml_features_db'},
    ResultConfiguration={
        'OutputLocation': 's3://my-lake/athena-results/'
    }
)

# Wait for results and load into SageMaker
# ... training code ...

# Alternatively, use Glue catalog directly
from awsglue.context import GlueContext
from pyspark.context import SparkContext

sc = SparkContext()
glueContext = GlueContext(sc)

# Read from Lake Formation
training_data = glueContext.create_dynamic_frame.from_catalog(
    database="ml_features_db",
    table_name="customer_churn_features"
)

# Convert to pandas for sklearn, or keep as Spark DF
pandas_df = training_data.toDF().toPandas()

# Train model
# ...
```

---

## 🧪 7. HANDS-ON LABS

### LAB 1: CREATE DATA LAKE WITH LAKE FORMATION (Console)

#### Step 1: Enable Lake Formation & Create Admin

```
1. Open AWS Lake Formation Console
   https://console.aws.amazon.com/lakeformation

2. Get Started → Add yourself as Data Lake Administrator
   ├─ IAM users and roles: Select your IAM user
   └─ Click "Get Started"

3. Verify administrator access
   ├─ You should see "Dashboard" with options
   └─ If not, check IAM permissions
```

---

#### Step 2: Register S3 Location

```
1. In Lake Formation Console:
   ├─ Navigate to "Data lake locations"
   └─ Click "Register location"

2. Configure:
   ├─ Amazon S3 path: s3://my-data-lake-ACCOUNT_ID/
   ├─ IAM role: Create new role
   │   └─ Lake Formation will create role automatically
   └─ Click "Register location"

3. Verify:
   └─ Location shows "Active" status
```

---

#### Step 3: Create Database

```
1. Navigate to "Databases"
2. Click "Create database"

3. Configure:
   ├─ Name: ecommerce_db
   ├─ Description: E-commerce analytics database
   ├─ Location: s3://my-data-lake-ACCOUNT_ID/ecommerce/
   └─ Click "Create database"
```

---

#### Step 4: Use Blueprint to Ingest Data

```
1. Navigate to "Blueprints" → "Use blueprints"

2. Select: "Database snapshot" blueprint

3. Import source:
   ├─ Blueprint type: Database snapshot
   ├─ Database connection: Create new connection
   │   ├─ Connection name: mysql-prod
   │   ├─ Connection type: MySQL
   │   ├─ Database: production_db
   │   ├─ Instance/Host: mysql.xxxxx.rds.amazonaws.com
   │   ├─ Port: 3306
   │   ├─ Username: admin
   │   └─ Password: (use Secrets Manager)
   └─ Click "Create connection"

4. Import target:
   ├─ Database: ecommerce_db
   ├─ Target storage location: s3://my-data-lake/raw/mysql/
   ├─ Data format: Parquet
   └─ Compression: Snappy

5. Import options:
   ├─ Table prefix: rds_
   ├─ Include tables: customers, orders, products
   └─ Workflow name: mysql_daily_snapshot

6. Schedule:
   ├─ Frequency: Daily
   ├─ Start time: 02:00 AM UTC
   └─ Click "Create"

Lake Formation creates:
├─ Glue crawler
├─ Glue ETL job
├─ CloudWatch schedule
└─ Tables in catalog (automatically)
```

---

#### Step 5: Grant Permissions

```
1. Navigate to "Permissions" → "Grant"

2. Grant database access:
   ├─ Principals: IAM user "data-analyst"
   ├─ LF-Tags or catalog resources: Named data catalog resources
   ├─ Databases: ecommerce_db
   ├─ Database permissions: Describe
   └─ Click "Grant"

3. Grant table access:
   ├─ Principals: IAM user "data-analyst"
   ├─ Database: ecommerce_db
   ├─ Tables: All tables
   ├─ Table permissions: Select
   ├─ Data permissions: 
   │   ├─ Column-based access: Include columns
   │   ├─ All columns EXCEPT: [ssn, credit_card, password]
   │   └─ Data filter: None (all rows)
   └─ Click "Grant"
```

---

#### Step 6: Query with Athena

```
1. Open Athena Console

2. Create workgroup (one-time):
   ├─ Name: lake-formation-workgroup
   └─ Query result location: s3://my-athena-results/

3. Run query:

SELECT 
    customer_id,
    name,
    email,
    -- ssn,  ← This column blocked by Lake Formation
    city,
    state
FROM ecommerce_db.customers
LIMIT 10;

4. Verify:
   ├─ Query succeeds
   ├─ Sensitive columns (ssn) not returned
   └─ Query fast (using Parquet)
```

---

### LAB 2: CREATE DATA LAKE WITH CLI/CloudShell

```bash
#!/bin/bash
# Complete Lake Formation Setup via CLI

# =====================================================
# VARIABLES
# =====================================================

export AWS_REGION="us-east-1"
export ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
export BUCKET_NAME="data-lake-${ACCOUNT_ID}"
export DATABASE_NAME="sales_analytics"
export ADMIN_USER_ARN="arn:aws:iam::${ACCOUNT_ID}:user/admin"

# =====================================================
# STEP 1: Create S3 Bucket
# =====================================================

echo "Creating S3 bucket..."
aws s3 mb s3://${BUCKET_NAME} --region ${AWS_REGION}

# Create folder structure
aws s3api put-object --bucket ${BUCKET_NAME} --key raw/
aws s3api put-object --bucket ${BUCKET_NAME} --key processed/
aws s3api put-object --bucket ${BUCKET_NAME} --key curated/

# =====================================================
# STEP 2: Create IAM Role for Lake Formation
# =====================================================

echo "Creating IAM role..."

# Trust policy
cat > lf-trust-policy.json <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": "lakeformation.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
EOF

# Create role
aws iam create-role \
  --role-name LakeFormationServiceRole \
  --assume-role-policy-document file://lf-trust-policy.json

# Attach policies
aws iam attach-role-policy \
  --role-name LakeFormationServiceRole \
  --policy-arn arn:aws:iam::aws:policy/AWSLakeFormationDataAdmin

# S3 access policy
cat > lf-s3-policy.json <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "s3:GetObject",
        "s3:PutObject",
        "s3:DeleteObject"
      ],
      "Resource": "arn:aws:s3:::${BUCKET_NAME}/*"
    },
    {
      "Effect": "Allow",
      "Action": [
        "s3:ListBucket"
      ],
      "Resource": "arn:aws:s3:::${BUCKET_NAME}"
    }
  ]
}
EOF

aws iam put-role-policy \
  --role-name LakeFormationServiceRole \
  --policy-name S3Access \
  --policy-document file://lf-s3-policy.json

# =====================================================
# STEP 3: Register S3 Location with Lake Formation
# =====================================================

echo "Registering S3 location..."

aws lakeformation register-resource \
  --resource-arn arn:aws:s3:::${BUCKET_NAME} \
  --use-service-linked-role

# Verify registration
aws lakeformation list-resources \
  --query 'ResourceInfoList[*].[ResourceArn,LastModified]' \
  --output table

# =====================================================
# STEP 4: Grant Data Lake Admin Permissions
# =====================================================

echo "Granting admin permissions..."

aws lakeformation grant-permissions \
  --principal DataLakePrincipalIdentifier=${ADMIN_USER_ARN} \
  --permissions CREATE_DATABASE DROP \
  --resource '{"Catalog": {}}'

# =====================================================
# STEP 5: Create Database
# =====================================================

echo "Creating database..."

aws glue create-database \
  --database-input "{
    \"Name\": \"${DATABASE_NAME}\",
    \"Description\": \"Sales analytics database\",
    \"LocationUri\": \"s3://${BUCKET_NAME}/curated/\"
  }"

# Grant admin permissions on database
aws lakeformation grant-permissions \
  --principal DataLakePrincipalIdentifier=${ADMIN_USER_ARN} \
  --permissions ALL \
  --resource "{
    \"Database\": {
      \"Name\": \"${DATABASE_NAME}\"
    }
  }"

# =====================================================
# STEP 6: Upload Sample Data
# =====================================================

echo "Creating sample data..."

# Create CSV file
cat > customers.csv <<EOF
customer_id,name,email,city,state,country
1,John Doe,john@example.com,New York,NY,USA
2,Jane Smith,jane@example.com,Los Angeles,CA,USA
3,Bob Johnson,bob@example.com,Chicago,IL,USA
4,Alice Brown,alice@example.com,Houston,TX,USA
5,Charlie Wilson,charlie@example.com,Phoenix,AZ,USA
EOF

# Upload to S3
aws s3 cp customers.csv s3://${BUCKET_NAME}/raw/customers/

# =====================================================
# STEP 7: Create Glue Crawler
# =====================================================

echo "Creating Glue crawler..."

aws glue create-crawler \
  --name sales-crawler \
  --role LakeFormationServiceRole \
  --database-name ${DATABASE_NAME} \
  --targets "{
    \"S3Targets\": [
      {
        \"Path\": \"s3://${BUCKET_NAME}/raw/customers/\"
      }
    ]
  }" \
  --schema-change-policy '{
    "UpdateBehavior": "UPDATE_IN_DATABASE",
    "DeleteBehavior": "LOG"
  }' \
  --configuration '{
    "Version": 1.0,
    "CrawlerOutput": {
      "Partitions": {"AddOrUpdateBehavior": "InheritFromTable"}
    }
  }'

# Run crawler
echo "Running crawler..."
aws glue start-crawler --name sales-crawler

# Wait for crawler to complete
echo "Waiting for crawler to complete..."
while true; do
  STATUS=$(aws glue get-crawler --name sales-crawler --query 'Crawler.State' --output text)
  if [ "$STATUS" = "READY" ]; then
    break
  fi
  echo "Crawler status: $STATUS"
  sleep 10
done

```bash
# =====================================================
# STEP 8: Verify Table Created (continued)
# =====================================================

echo "Verifying table creation..."

# List tables in database
aws glue get-tables \
  --database-name ${DATABASE_NAME} \
  --query 'TableList[*].[Name,StorageDescriptor.Location]' \
  --output table

# Get table details
TABLE_NAME=$(aws glue get-tables \
  --database-name ${DATABASE_NAME} \
  --query 'TableList[0].Name' \
  --output text)

echo "Table created: ${TABLE_NAME}"

# View table schema
aws glue get-table \
  --database-name ${DATABASE_NAME} \
  --name ${TABLE_NAME} \
  --query 'Table.StorageDescriptor.Columns[*].[Name,Type]' \
  --output table

# =====================================================
# STEP 9: Create Data Analyst User and Grant Permissions
# =====================================================

echo "Setting up data analyst permissions..."

# Create analyst IAM user (if doesn't exist)
aws iam create-user --user-name data-analyst 2>/dev/null || echo "User exists"

# Grant Lake Formation permissions with column filtering
aws lakeformation grant-permissions \
  --principal DataLakePrincipalIdentifier=arn:aws:iam::${ACCOUNT_ID}:user/data-analyst \
  --permissions SELECT \
  --resource "{
    \"TableWithColumns\": {
      \"DatabaseName\": \"${DATABASE_NAME}\",
      \"Name\": \"${TABLE_NAME}\",
      \"ColumnNames\": [\"customer_id\", \"name\", \"city\", \"state\", \"country\"]
    }
  }"

echo "Permissions granted to data-analyst"

# =====================================================
# STEP 10: Set Up Row-Level Security (Data Filter)
# =====================================================

echo "Creating data filter for row-level security..."

# Create data filter expression
aws lakeformation create-data-cells-filter \
  --table-data "{
    \"TableCatalogId\": \"${ACCOUNT_ID}\",
    \"DatabaseName\": \"${DATABASE_NAME}\",
    \"TableName\": \"${TABLE_NAME}\",
    \"Name\": \"us_only_filter\",
    \"RowFilter\": {
      \"FilterExpression\": \"country='USA'\"
    },
    \"ColumnNames\": [\"customer_id\", \"name\", \"city\", \"state\"],
    \"ColumnWildcard\": {}
  }"

# Grant permissions on filtered view
aws lakeformation grant-permissions \
  --principal DataLakePrincipalIdentifier=arn:aws:iam::${ACCOUNT_ID}:user/data-analyst \
  --permissions SELECT \
  --resource "{
    \"DataCellsFilter\": {
      \"TableCatalogId\": \"${ACCOUNT_ID}\",
      \"DatabaseName\": \"${DATABASE_NAME}\",
      \"TableName\": \"${TABLE_NAME}\",
      \"Name\": \"us_only_filter\"
    }
  }"

# =====================================================
# STEP 11: Create LF-Tags for Tag-Based Access Control
# =====================================================

echo "Setting up LF-Tags..."

# Create Classification tag
aws lakeformation create-lf-tag \
  --tag-key Classification \
  --tag-values "Public" "Internal" "Confidential" "Restricted"

# Create Department tag
aws lakeformation create-lf-tag \
  --tag-key Department \
  --tag-values "Sales" "Marketing" "Engineering" "Finance"

# Tag the database
aws lakeformation add-lf-tags-to-resource \
  --resource "{
    \"Database\": {
      \"Name\": \"${DATABASE_NAME}\"
    }
  }" \
  --lf-tags "[
    {\"TagKey\": \"Classification\", \"TagValues\": [\"Internal\"]},
    {\"TagKey\": \"Department\", \"TagValues\": [\"Sales\"]}
  ]"

# Tag the table
aws lakeformation add-lf-tags-to-resource \
  --resource "{
    \"Table\": {
      \"DatabaseName\": \"${DATABASE_NAME}\",
      \"Name\": \"${TABLE_NAME}\"
    }
  }" \
  --lf-tags "[
    {\"TagKey\": \"Classification\", \"TagValues\": [\"Internal\"]},
    {\"TagKey\": \"Department\", \"TagValues\": [\"Sales\"]}
  ]"

# Grant tag-based permissions
aws lakeformation grant-permissions \
  --principal DataLakePrincipalIdentifier=arn:aws:iam::${ACCOUNT_ID}:user/data-analyst \
  --permissions SELECT \
  --resource "{
    \"LFTagPolicy\": {
      \"ResourceType\": \"TABLE\",
      \"Expression\": [
        {\"TagKey\": \"Classification\", \"TagValues\": [\"Public\", \"Internal\"]},
        {\"TagKey\": \"Department\", \"TagValues\": [\"Sales\"]}
      ]
    }
  }"

# =====================================================
# STEP 12: Query Data with Athena
# =====================================================

echo "Setting up Athena..."

# Create Athena workgroup
aws athena create-work-group \
  --name lake-formation-workgroup \
  --configuration "{
    \"ResultConfigurationUpdates\": {
      \"OutputLocation\": \"s3://${BUCKET_NAME}/athena-results/\"
    },
    \"EnforceWorkGroupConfiguration\": true
  }"

# Execute query
QUERY_EXECUTION_ID=$(aws athena start-query-execution \
  --query-string "SELECT * FROM ${DATABASE_NAME}.${TABLE_NAME} LIMIT 10" \
  --query-execution-context "Database=${DATABASE_NAME}" \
  --result-configuration "OutputLocation=s3://${BUCKET_NAME}/athena-results/" \
  --work-group lake-formation-workgroup \
  --query 'QueryExecutionId' \
  --output text)

echo "Query submitted: ${QUERY_EXECUTION_ID}"

# Wait for query completion
echo "Waiting for query to complete..."
while true; do
  STATUS=$(aws athena get-query-execution \
    --query-execution-id ${QUERY_EXECUTION_ID} \
    --query 'QueryExecution.Status.State' \
    --output text)
  
  if [ "$STATUS" = "SUCCEEDED" ]; then
    echo "Query completed successfully!"
    break
  elif [ "$STATUS" = "FAILED" ]; then
    echo "Query failed!"
    aws athena get-query-execution \
      --query-execution-id ${QUERY_EXECUTION_ID} \
      --query 'QueryExecution.Status.StateChangeReason'
    break
  fi
  
  echo "Query status: $STATUS"
  sleep 3
done

# Get query results
aws athena get-query-results \
  --query-execution-id ${QUERY_EXECUTION_ID} \
  --query 'ResultSet.Rows[*].Data[*].VarCharValue' \
  --output table

# =====================================================
# STEP 13: Set Up Cross-Account Sharing (Optional)
# =====================================================

echo "Setting up cross-account sharing..."

# Example: Share with another AWS account (replace with actual account ID)
CONSUMER_ACCOUNT="999999999999"  # Replace with actual account

# Create resource share
aws ram create-resource-share \
  --name sales-data-share \
  --resource-arns "arn:aws:glue:${AWS_REGION}:${ACCOUNT_ID}:table/${DATABASE_NAME}/${TABLE_NAME}" \
  --principals "arn:aws:iam::${CONSUMER_ACCOUNT}:root" \
  --tags "Key=Purpose,Value=DataSharing"

# Grant Lake Formation permissions to consumer account
aws lakeformation grant-permissions \
  --principal DataLakePrincipalIdentifier=${CONSUMER_ACCOUNT} \
  --permissions SELECT DESCRIBE \
  --resource "{
    \"Table\": {
      \"DatabaseName\": \"${DATABASE_NAME}\",
      \"Name\": \"${TABLE_NAME}\",
      \"CatalogId\": \"${ACCOUNT_ID}\"
    }
  }"

# =====================================================
# STEP 14: Enable Audit Logging
# =====================================================

echo "Enabling audit logging..."

# Create CloudWatch log group
aws logs create-log-group \
  --log-group-name /aws/lakeformation/audit

# Update Lake Formation settings for audit logs
aws lakeformation put-data-lake-settings \
  --data-lake-settings "{
    \"DataLakeAdmins\": [
      {\"DataLakePrincipalIdentifier\": \"${ADMIN_USER_ARN}\"}
    ],
    \"CreateDatabaseDefaultPermissions\": [],
    \"CreateTableDefaultPermissions\": []
  }"

# =====================================================
# STEP 15: Create Sample ETL Job (Glue)
# =====================================================

echo "Creating Glue ETL job..."

# Create ETL script
cat > etl_script.py <<'PYEOF'
import sys
from awsglue.transforms import *
from awsglue.utils import getResolvedOptions
from pyspark.context import SparkContext
from awsglue.context import GlueContext
from awsglue.job import Job

args = getResolvedOptions(sys.argv, ['JOB_NAME', 'DATABASE', 'TABLE', 'OUTPUT_PATH'])

sc = SparkContext()
glueContext = GlueContext(sc)
spark = glueContext.spark_session
job = Job(glueContext)
job.init(args['JOB_NAME'], args)

# Read from Lake Formation catalog
source_df = glueContext.create_dynamic_frame.from_catalog(
    database = args['DATABASE'],
    table_name = args['TABLE']
)

# Transform: Add derived columns
from pyspark.sql.functions import upper, concat, lit
df = source_df.toDF()
df_transformed = df.withColumn("full_location", 
    concat(df["city"], lit(", "), df["state"], lit(", "), df["country"])
)

# Convert back to DynamicFrame
output_df = DynamicFrame.fromDF(df_transformed, glueContext, "output_df")

# Write to S3 in Parquet format
glueContext.write_dynamic_frame.from_options(
    frame = output_df,
    connection_type = "s3",
    connection_options = {"path": args['OUTPUT_PATH']},
    format = "parquet"
)

job.commit()
PYEOF

# Upload script to S3
aws s3 cp etl_script.py s3://${BUCKET_NAME}/scripts/

# Create Glue job
aws glue create-job \
  --name customer-etl-job \
  --role LakeFormationServiceRole \
  --command "{
    \"Name\": \"glueetl\",
    \"ScriptLocation\": \"s3://${BUCKET_NAME}/scripts/etl_script.py\",
    \"PythonVersion\": \"3\"
  }" \
  --default-arguments "{
    \"--DATABASE\": \"${DATABASE_NAME}\",
    \"--TABLE\": \"${TABLE_NAME}\",
    \"--OUTPUT_PATH\": \"s3://${BUCKET_NAME}/processed/customers/\",
    \"--enable-glue-datacatalog\": \"true\"
  }" \
  --max-capacity 2.0

# Run ETL job
JOB_RUN_ID=$(aws glue start-job-run \
  --job-name customer-etl-job \
  --query 'JobRunId' \
  --output text)

echo "ETL job started: ${JOB_RUN_ID}"

# =====================================================
# STEP 16: Set Up Data Quality Checks
# =====================================================

echo "Creating data quality ruleset..."

# Create data quality ruleset
cat > dq_rules.json <<EOF
{
  "Name": "customer_data_quality",
  "Description": "Quality checks for customer data",
  "Ruleset": "Rules = [
    ColumnExists \"customer_id\",
    IsComplete \"customer_id\",
    IsUnique \"customer_id\",
    ColumnValues \"country\" in [\"USA\", \"Canada\", \"UK\"],
    RowCount between 1 and 1000000
  ]"
}
EOF

# =====================================================
# STEP 17: Monitor and View Permissions
# =====================================================

echo "Viewing current permissions..."

# List all permissions for the database
aws lakeformation list-permissions \
  --resource "{
    \"Database\": {
      \"Name\": \"${DATABASE_NAME}\"
    }
  }" \
  --query 'PrincipalResourcePermissions[*].[Principal.DataLakePrincipalIdentifier,Permissions]' \
  --output table

# List all permissions for the table
aws lakeformation list-permissions \
  --resource "{
    \"Table\": {
      \"DatabaseName\": \"${DATABASE_NAME}\",
      \"Name\": \"${TABLE_NAME}\"
    }
  }" \
  --query 'PrincipalResourcePermissions[*].[Principal.DataLakePrincipalIdentifier,Permissions,PermissionsWithGrantOption]' \
  --output table

# List all LF-Tags
aws lakeformation list-lf-tags \
  --query 'LFTags[*].[TagKey,TagValues]' \
  --output table

# =====================================================
# STEP 18: Create Monitoring Dashboard
# =====================================================

echo "Setting up CloudWatch monitoring..."

# Create CloudWatch dashboard
cat > dashboard.json <<EOF
{
  "widgets": [
    {
      "type": "metric",
      "properties": {
        "metrics": [
          [ "AWS/Glue", "glue.driver.aggregate.numCompletedTasks", { "stat": "Sum" } ],
          [ ".", "glue.driver.aggregate.numFailedTasks", { "stat": "Sum" } ]
        ],
        "period": 300,
        "stat": "Average",
        "region": "${AWS_REGION}",
        "title": "Glue Job Metrics"
      }
    },
    {
      "type": "log",
      "properties": {
        "query": "SOURCE '/aws/lakeformation/audit' | fields @timestamp, eventName, userIdentity.principalId | sort @timestamp desc | limit 20",
        "region": "${AWS_REGION}",
        "title": "Lake Formation Audit Logs"
      }
    }
  ]
}
EOF

aws cloudwatch put-dashboard \
  --dashboard-name LakeFormationMonitoring \
  --dashboard-body file://dashboard.json

# =====================================================
# SUMMARY OUTPUT
# =====================================================

echo ""
echo "=============================================="
echo "✅ LAKE FORMATION SETUP COMPLETE!"
echo "=============================================="
echo ""
echo "📊 Resources Created:"
echo "   • S3 Bucket: ${BUCKET_NAME}"
echo "   • Database: ${DATABASE_NAME}"
echo "   • Table: ${TABLE_NAME}"
echo "   • IAM Role: LakeFormationServiceRole"
echo "   • Glue Crawler: sales-crawler"
echo "   • Glue ETL Job: customer-etl-job"
echo "   • Athena Workgroup: lake-formation-workgroup"
echo ""
echo "🔐 Security Configured:"
echo "   • Column-level filtering enabled"
echo "   • Row-level security (data filters)"
echo "   • LF-Tags: Classification, Department"
echo "   • Audit logging enabled"
echo ""
echo "🔗 Connection Details:"
echo "   • Athena Query: https://console.aws.amazon.com/athena"
echo "   • Lake Formation: https://console.aws.amazon.com/lakeformation"
echo "   • CloudWatch Dashboard: LakeFormationMonitoring"
echo ""
echo "📝 Next Steps:"
echo "   1. Query data: aws athena start-query-execution ..."
echo "   2. View permissions: aws lakeformation list-permissions ..."
echo "   3. Monitor: Check CloudWatch dashboard"
echo "   4. Add more data sources using blueprints"
echo ""
echo "=============================================="
```

---

### LAB 3: ADVANCED SCENARIOS

#### Scenario 1: Incremental Data Loading

```bash
#!/bin/bash
# Incremental load with bookmarks

# Create incremental load blueprint
cat > incremental_blueprint.json <<EOF
{
  "BlueprintName": "incremental-database-load",
  "SourceConfig": {
    "DatabaseType": "MYSQL",
    "ConnectionName": "mysql-prod",
    "DatabaseName": "production",
    "TableName": "orders",
    "IncrementalColumn": "updated_at"
  },
  "TargetConfig": {
    "DatabaseName": "sales_analytics",
    "S3Location": "s3://${BUCKET_NAME}/incremental/orders/",
    "Format": "PARQUET",
    "PartitionKeys": ["year", "month", "day"]
  },
  "Schedule": {
    "Type": "CRON",
    "Expression": "cron(0 * * * ? *)"
  }
}
EOF

# Create workflow from blueprint
aws lakeformation create-workflow \
  --workflow-input file://incremental_blueprint.json
```

---

#### Scenario 2: Machine Learning Feature Store

```python
# Create ML feature tables in Lake Formation

import boto3
import pandas as pd
from datetime import datetime, timedelta

glue = boto3.client('glue')
s3 = boto3.client('s3')

# Generate ML features
def create_customer_features():
    # Simulate feature engineering
    features = pd.DataFrame({
        'customer_id': range(1, 1001),
        'total_orders': np.random.randint(1, 100, 1000),
        'avg_order_value': np.random.uniform(10, 500, 1000),
        'days_since_last_order': np.random.randint(0, 365, 1000),
        'churn_risk_score': np.random.uniform(0, 1, 1000),
        'feature_timestamp': datetime.now()
    })
    
    return features

# Save to S3
features = create_customer_features()
features.to_parquet('s3://my-lake/ml-features/customer_features.parquet')

# Create table in catalog
glue.create_table(
    DatabaseName='ml_features_db',
    TableInput={
        'Name': 'customer_features',
        'StorageDescriptor': {
            'Columns': [
                {'Name': 'customer_id', 'Type': 'bigint'},
                {'Name': 'total_orders', 'Type': 'int'},
                {'Name': 'avg_order_value', 'Type': 'double'},
                {'Name': 'days_since_last_order', 'Type': 'int'},
                {'Name': 'churn_risk_score', 'Type': 'double'},
                {'Name': 'feature_timestamp', 'Type': 'timestamp'}
            ],
            'Location': 's3://my-lake/ml-features/',
            'InputFormat': 'org.apache.hadoop.hive.ql.io.parquet.MapredParquetInputFormat',
            'OutputFormat': 'org.apache.hadoop.hive.ql.io.parquet.MapredParquetOutputFormat',
            'SerdeInfo': {
                'SerializationLibrary': 'org.apache.hadoop.hive.ql.io.parquet.serde.ParquetHiveSerDe'
            }
        },
        'Parameters': {
            'classification': 'parquet',
            'feature_group': 'customer_churn'
        }
    }
)

# Tag as ML features
lakeformation = boto3.client('lakeformation')
lakeformation.add_lf_tags_to_resource(
    Resource={
        'Table': {
            'DatabaseName': 'ml_features_db',
            'Name': 'customer_features'
        }
    },
    LFTags=[
        {'TagKey': 'DataType', 'TagValues': ['MLFeatures']},
        {'TagKey': 'UseCase', 'TagValues': ['ChurnPrediction']}
    ]
)
```

---

#### Scenario 3: Real-Time Streaming Pipeline

```python
# Lake Formation + Kinesis for real-time analytics

import boto3
import json
from datetime import datetime

# Kinesis Firehose to Lake Formation
firehose = boto3.client('firehose')

# Create delivery stream
firehose.create_delivery_stream(
    DeliveryStreamName='realtime-events-to-lake',
    DeliveryStreamType='DirectPut',
    ExtendedS3DestinationConfiguration={
        'RoleARN': 'arn:aws:iam::ACCOUNT:role/FirehoseRole',
        'BucketARN': 'arn:aws:s3:::my-data-lake',
        'Prefix': 'streaming/events/year=!{timestamp:yyyy}/month=!{timestamp:MM}/day=!{timestamp:dd}/hour=!{timestamp:HH}/',
        'ErrorOutputPrefix': 'streaming/errors/',
        'BufferingHints': {
            'SizeInMBs': 5,
            'IntervalInSeconds': 60
        },
        'CompressionFormat': 'GZIP',
        'DataFormatConversionConfiguration': {
            'Enabled': True,
            'SchemaConfiguration': {
                'DatabaseName': 'streaming_db',
                'TableName': 'events',
                'Region': 'us-east-1',
                'RoleARN': 'arn:aws:iam::ACCOUNT:role/FirehoseRole'
            },
            'OutputFormatConfiguration': {
                'Serializer': {
                    'ParquetSerDe': {
                        'Compression': 'SNAPPY'
                    }
                }
            }
        },
        'ProcessingConfiguration': {
            'Enabled': True,
            'Processors': [
                {
                    'Type': 'Lambda',
                    'Parameters': [
                        {
                            'ParameterName': 'LambdaArn',
                            'ParameterValue': 'arn:aws:lambda:REGION:ACCOUNT:function:EnrichEvents'
                        }
                    ]
                }
            ]
        }
    }
)

# Glue crawler for streaming data (runs every 5 minutes)
glue = boto3.client('glue')
glue.create_crawler(
    Name='streaming-events-crawler',
    Role='AWSGlueServiceRole-LakeFormation',
    DatabaseName='streaming_db',
    Targets={
        'S3Targets': [
            {
                'Path': 's3://my-data-lake/streaming/events/'
            }
        ]
    },
    Schedule='cron(*/5 * * * ? *)',  # Every 5 minutes
    SchemaChangePolicy={
        'UpdateBehavior': 'UPDATE_IN_DATABASE',
        'DeleteBehavior': 'LOG'
    }
)

# Query near-real-time data with Athena
athena = boto3.client('athena')
response = athena.start_query_execution(
    QueryString='''
        SELECT 
            event_type,
            COUNT(*) as event_count,
            DATE_TRUNC('minute', event_timestamp) as minute
        FROM streaming_db.events
        WHERE event_timestamp >= CURRENT_TIMESTAMP - INTERVAL '15' MINUTE
        GROUP BY event_type, DATE_TRUNC('minute', event_timestamp)
        ORDER BY minute DESC
    ''',
    QueryExecutionContext={'Database': 'streaming_db'},
    ResultConfiguration={
        'OutputLocation': 's3://my-data-lake/athena-results/'
    }
)
```

---

## 🎯 8. BEST PRACTICES

### Security Best Practices

#### 1. **Principle of Least Privilege**

```
❌ BAD: Grant broad permissions
aws lakeformation grant-permissions \
  --principal IAM_USER \
  --permissions ALL \
  --resource '{"Catalog": {}}'

✅ GOOD: Grant specific permissions
aws lakeformation grant-permissions \
  --principal IAM_USER \
  --permissions SELECT DESCRIBE \
  --resource '{
    "TableWithColumns": {
      "DatabaseName": "analytics_db",
      "Name": "customers",
      "ColumnNames": ["id", "name", "email"]
    }
  }'
```

---

#### 2. **Use LF-Tags for Scale**

```
❌ BAD: Individual table grants (doesn't scale)
For each of 1000 tables:
  Grant permissions to analyst_team

✅ GOOD: Tag-based grants (scales easily)
1. Tag tables with: Sensitivity=Internal, Dept=Sales
2. Grant once: analyst_team can access Sensitivity=Internal

New tables auto-inherit permissions!
```

---

#### 3. **Enable Audit Logging**

```bash
# Enable CloudTrail for Lake Formation
aws cloudtrail create-trail \
  --name lakeformation-audit \
  --s3-bucket-name audit-logs-bucket

aws cloudtrail start-logging --name lakeformation-audit

# Enable Lake Formation CloudWatch logging
aws lakeformation put-data-lake-settings \
  --data-lake-settings '{
    "DataLakeAdmins": [...],
    "CreateDatabaseDefaultPermissions": [],
    "CreateTableDefaultPermissions": [],
    "TrustedResourceOwners": [],
    "AllowExternalDataFiltering": true
  }'

# Query audit logs
SELECT 
    useridentity.principalid,
    eventname,
    requestparameters,
    eventtime
FROM cloudtrail_logs
WHERE eventname LIKE '%LakeFormation%'
ORDER BY eventtime DESC;
```

---

### Performance Best Practices

#### 1. **Optimize File Formats**

```
CSV Performance:     ⭐ (1x baseline)
JSON Performance:    ⭐ (0.8x)
Avro Performance:    ⭐⭐ (2x)
Parquet Performance: ⭐⭐⭐⭐⭐ (10x)  ← USE THIS!
ORC Performance:     ⭐⭐⭐⭐ (8x)

Always use Parquet or ORC for analytics!
```

---

#### 2. **Partition Strategically**

```sql
-- ❌ BAD: No partitioning
SELECT * FROM orders 
WHERE order_date = '2024-01-15'
-- Scans: 10 TB (entire table)
-- Cost: $50
-- Time: 5 minutes

-- ✅ GOOD: Partitioned by date
CREATE TABLE orders (
    order_id BIGINT,
    amount DECIMAL
)
PARTITIONED BY (year INT, month INT, day INT)
STORED AS PARQUET;

SELECT * FROM orders 
WHERE year=2024 AND month=1 AND day=15
-- Scans: 10 GB (one partition)
-- Cost: $0.05
-- Time: 3 seconds
```

**Partitioning Guidelines:**
- ✅ Partition by frequently filtered columns (date, region)
- ✅ Keep partitions between 10 MB - 1 GB
- ❌ Don't create >10,000 partitions (slows metadata operations)
- ❌ Don't partition by high-cardinality columns (user_id)

---

#### 3. **Compress Data**

```
Compression Comparison (1 GB uncompressed):

None:    1000 MB, Fast Query
GZIP:    250 MB,  Slow Query   (CPU intensive)
Snappy:  400 MB,  Fast Query   ← RECOMMENDED!
LZO:     380 MB,  Fast Query
ZSTD:    220 MB,  Medium Query

Best choice: Snappy (good compression + fast queries)
```

---

#### 4. **Use Columnar Storage**

```
Row-based (CSV):
┌──────────────────────────────────────┐
│ id | name  | email | city | state   │
│ 1  | John  | j@... | NYC  | NY      │
│ 2  | Jane  | j@... | LA   | CA      │
└──────────────────────────────────────┘
Query "SELECT city FROM table" → Reads ALL columns

Columnar (Parquet):
┌────┐ ┌──────┐ ┌───────┐ ┌──────┐ ┌───────┐
│ id │ │ name │ │ email │ │ city │ │ state │
├────┤ ├──────┤ ├───────┤ ├──────┤ ├───────┤
│ 1  │ │ John │ │ j@... │ │ NYC  │ │ NY    │
│ 2  │ │ Jane │ │ j@... │ │ LA   │ │ CA    │
└────┘ └──────┘ └───────┘ └──────┘ └───────┘
Query "SELECT city FROM table" → Reads ONLY city column!

Result: 10-100x faster queries!
```

---

### Cost Optimization

#### 1. **Lifecycle Policies**

```bash
# Move old data to cheaper storage

aws s3api put-bucket-lifecycle-configuration \
  --bucket my-data-lake \
  --lifecycle-configuration '{
    "Rules": [
      {
        "Id": "ArchiveOldData",
        "Status": "Enabled",
        "Transitions": [
          {
            "Days": 90,
            "StorageClass": "INTELLIGENT_TIERING"
          },
          {
            "Days": 365,
            "StorageClass": "GLACIER"
          },
          {
            "Days": 2555,
            "StorageClass": "DEEP_ARCHIVE"
          }
        ],
        "Expiration": {
          "Days": 2555
        }
      }
    ]
  }'

Cost Savings:
├─ S3 Standard: $0.023/GB/month
├─ S3 Intelligent-Tiering: $0.0125/GB/month (45% savings)
├─ S3 Glacier: $0.004/GB/month (83% savings)
└─ S3 Glacier Deep Archive: $0.00099/GB/month (96% savings!)
```

---

#### 2. **Optimize Query Costs**

```sql
-- ❌ EXPENSIVE: Select all columns
SELECT * FROM large_table
WHERE date = '2024-01-15'
-- Scans: 1 TB
-- Cost: $5

-- ✅ CHEAP: Select only needed columns
SELECT customer_id, amount FROM large_table
WHERE date = '2024-01-15'
-- Scans: 50 GB (only 2 columns)
-- Cost: $0.25 (20x cheaper!)
```

---

#### 3. **Use Glue ETL Wisely**

```
Glue DPU Pricing:
├─ Standard: $0.44/DPU-Hour
└─ G.2X: $0.88/DPU-Hour (2x memory/compute)

Optimization:
├─ Use partitioning to process only new data
├─ Use job bookmarks to track processed data
├─ Filter early in ETL pipeline
└─ Use appropriate DPU size (don't over-provision)

Example:
❌ Process entire 10 TB daily: $440/day
✅ Process only new 100 GB: $4.40/day (99% savings!)
```

---

## 🚨 9. TROUBLESHOOTING & MONITORING

### Common Issues & Solutions

#### Issue 1: "Access Denied" When Querying

```
ERROR: Access Denied

ROOT CAUSES:
1. Missing Lake Formation permissions
2. IAM policy conflicts
3. S3 bucket policy blocks access
4. Outdated IAM credentials

SOLUTION CHECKLIST:

□ Check Lake Formation permissions:
aws lakeformation list-permissions \
  --principal DataLakePrincipalIdentifier=USER_ARN \
  --resource '{"Table": {"DatabaseName": "DB", "Name": "TABLE"}}'

□ Verify IAM permissions:
aws iam simulate-principal-policy \
  --policy-source-arn USER_ARN \
  --action-names glue:GetTable s3:GetObject \
  --resource-arns TABLE_ARN S3_ARN

□ Check S3 bucket policy:
aws s3api get-bucket-policy --bucket BUCKET_NAME

□ Verify credentials:
aws sts get-caller-identity

QUICK FIX:
aws lakeformation grant-permissions \
  --principal DataLakePrincipalIdentifier=USER_ARN \
  --permissions SELECT DESCRIBE \
  --resource '{"Table": {"DatabaseName": "DB", "Name": "TABLE"}}'
```

---

#### Issue 2: Slow Queries

```
SYMPTOM: Athena queries taking >5 minutes

DIAGNOSIS:

1. Check data format:
aws glue get-table --database DB --name TABLE \
  --query 'Table.StorageDescriptor.SerdeInfo.SerializationLibrary'

❌ If CSV/JSON → Convert to Parquet

2. Check partitioning:
aws glue get-partitions --database DB --table TABLE \
  --max-results 10

❌ If no partitions → Add partitions

3. Check file sizes:
aws s3 ls s3://bucket/path/ --recursive --human-readable

❌ If many small files (<10 MB) → Compact files

SOLUTIONS:

□ Convert to Parquet:
-- Use Glue ETL or CTAS
CREATE TABLE new_table
WITH (format='PARQUET', parquet_compression='SNAPPY')
AS SELECT * FROM old_csv_table

□ Add partitions:
ALTER TABLE table_name 
ADD PARTITION (year=2024, month=1)
LOCATION 's3://bucket/year=2024/month=01/'

□ Compact small files:
-- Glue ETL job
output_df.coalesce(1).write.parquet(...)
```

---

#### Issue 3: Schema Mismatch

```
ERROR: HIVE_PARTITION_SCHEMA_MISMATCH

CAUSE: Partition schema doesn't match table schema

SOLUTION:

1. Drop and recreate partitions:
ALTER TABLE table_name DROP PARTITION (year=2024, month=1);
MSCK REPAIR TABLE table_name;

2. Or update schema:
aws glue update-partition \
  --database DB \
  --table TABLE \
  --partition-input '{
    "Values": ["2024", "1"],
    "StorageDescriptor": {
      "Columns": [...updated columns...]
    }
  }'

3. Or use schema-on-read (Athena):
SET hive.metastore.partition.inherit.table.properties=true;
```

---

### Monitoring Dashboard (CloudWatch)

```python
# Create comprehensive monitoring

import boto3

cloudwatch = boto3.client('cloudwatch')

# Put custom metrics
cloudwatch.put_metric_data(
    Namespace='LakeFormation',
    MetricData=[
        {
            'MetricName': 'TablesCreated',
            'Value': 10,
            'Unit': 'Count'
        },
        {
            'MetricName': 'PermissionsGranted',
            'Value': 25,
            'Unit': 'Count'
        },
        {
            'MetricName': 'DataSizeGB',
            'Value': 500.5,
            'Unit': 'Gigabytes'
        }
    ]
)

# Create alarms
cloudwatch.put_metric_alarm(
    AlarmName='HighQueryCost',
    ComparisonOperator='GreaterThanThreshold',
    EvaluationPeriods=1,
    MetricName='EstimatedCharges',
    Namespace='AWS/Billing',
    Period=3600,
    Statistic='Maximum',
    Threshold=100.0,
    ActionsEnabled=True,
    AlarmActions=['arn:aws:sns:REGION:ACCOUNT:alerts'],
    AlarmDescription='Alert when query costs exceed $100/hour'
)
```

---

## 📈 10. REAL-WORLD USE CASES

### Use Case 1: Healthcare Data Lake

```
SCENARIO: Hospital System with HIPAA Compliance

Requirements:
├─ Store patient records (structured + unstructured)
├─ HIPAA compliance (encryption, access logs)
├─ Row-level security (doctors see only their patients)
├─ Anonymized data for research
└─ Real-time patient monitoring

Architecture:
┌──────────────────────────────────────────────┐
│ Data Sources:                                 │
│ ├─ EHR Systems (Epic, Cerner)                │
│ ├─ Medical Devices (IoT sensors)             │
│ ├─ Lab Results (LIMS)                        │
│ └─ Imaging (PACS - DICOM files)              │
└────────────┬─────────────────────────────────┘
             ↓
┌────────────▼─────────────────────────────────┐
│ Lake Formation:                               │
│ ├─ Encryption: KMS (HIPAA-compliant keys)    │
│ ├─ LF-Tags:                                  │
│ │   ├─ PHI: [Identifiable, DeIdentified]    │
│ │   ├─ Department: [Cardiology, Oncology]   │
│ │   └─ Sensitivity: [Restricted, Research]  │
│ ├─ Row Filters:                              │
│ │   └─ doctor_id = CURRENT_USER              │
│ └─ Audit: All access logged to CloudTrail   │
└────────────┬─────────────────────────────────┘
             ↓
┌────────────▼─────────────────────────────────┐
│ Analytics:                                    │
│ ├─ Athena: Ad-hoc patient queries            │
│ ├─ QuickSight: Hospital dashboards           │
│ ├─ SageMaker: Predictive models (readmit)   │
│ └─ EMR: Genomics processing                  │
└──────────────────────────────────────────────┘

Implementation:
```

```sql
-- Patient data table with strict controls

CREATE TABLE patient_records (
    patient_id STRING,
    name STRING,
    ssn STRING,
    diagnosis STRING,
    doctor_id STRING,
    admit_date DATE,
    medical_images STRING  -- S3 paths to DICOM files
)
PARTITIONED BY (year INT, month INT)
STORED AS PARQUET
LOCATION 's3://hospital-lake/patients/';

-- Tag as PHI
aws lakeformation add-lf-tags-to-resource \
  --resource '{"Table": {"DatabaseName": "hospital_db", "Name": "patient_records"}}' \
  --lf-tags '[
    {"TagKey": "PHI", "TagValues": ["Identifiable"]},
    {"TagKey": "Compliance", "TagValues": ["HIPAA"]}
  ]'

-- Grant to doctors (row-level security)
aws lakeformation grant-permissions \
  --principal IAM_ROLE_DOCTORS \
  --permissions SELECT \
  --resource '{
    "DataCellsFilter": {
      "TableCatalogId": "ACCOUNT_ID",
      "DatabaseName": "hospital_db",
      "TableName": "patient_records",
      "Name": "doctor_patients_only",
      "RowFilter": {
        "FilterExpression": "doctor_id = SESSION_USER"
      }
    }
  }'

-- Grant to researchers (de-identified data only)
aws lakeformation grant-permissions \
  --principal IAM_ROLE_RESEARCHERS \
  --permissions SELECT \
  --resource '{
    "TableWithColumns": {
      "DatabaseName": "hospital_db",
      "Name": "patient_records",
      "ColumnNames": ["patient_id", "diagnosis", "admit_date"],
      "ColumnWildcard": {}
    }
  }'
  -- Excludes: name, ssn (de-identified!)
```

---

### Use Case 2: E-Commerce Analytics Platform

```
SCENARIO: Online Retailer with Multi-Channel Data

Data Sources:
├─ Website clickstream (real-time)
├─ Mobile app events (real-time)
├─ Order database (MySQL)
├─ Customer data (Salesforce)
├─ Product catalog (DynamoDB)
└─ Reviews/ratings (MongoDB)

Architecture:
```

```
Clickstream → Kinesis → Firehose → S3 (raw/)
                                      ↓
                            Lake Formation
                                      ↓
              ┌────────────────┬──────┴───────┬────────────┐
              ↓                ↓              ↓            ↓
          Athena          Redshift       QuickSight     SageMaker
      (Ad-hoc SQL)     (BI Queries)    (Dashboards)  (Recommendations)
```

```python
# Blueprint for e-commerce data ingestion

import boto3

lakeformation = boto3.client('lakeformation')

# Create blueprint for database snapshot
blueprint_config = {
    'BlueprintName': 'ecommerce-daily-snapshot',
    'Type': 'DATABASE_SNAPSHOT',
    'Source': {
        'DatabaseConnection': 'mysql-orders-db',
        'Tables': ['orders', 'order_items', 'customers', 'products']
    },
    'Target': {
        'Database': 'ecommerce_analytics',
        'S3Location': 's3://ecommerce-lake/curated/',
        'Format': 'PARQUET',
        'PartitionKeys': ['order_date']
    },
    'Transform': {
        'JoinCustomerData': True,
        'EnrichWithProductCatalog': True,
        'CalculateMetrics': ['lifetime_value', 'avg_order_value']
    },
    'Schedule': 'cron(0 2 * * ? *)'  # Daily at 2 AM
}

# Customer 360 view (unified customer profile)
customer_360_query = """
CREATE TABLE customer_360 AS
SELECT 
    c.customer_id,
    c.name,
    c.email,
    c.signup_date,
    COUNT(DISTINCT o.order_id) as total_orders,
    SUM(o.total_amount) as lifetime_value,
    AVG(o.total_amount) as avg_order_value,
    MAX(o.order_date) as last_order_date,
    DATEDIFF(CURRENT_DATE, MAX(o.order_date)) as days_since_last_order,
    COLLECT_LIST(o.product_category) as purchased_categories,
    AVG(r.rating) as avg_rating_given
FROM customers c
LEFT JOIN orders o ON c.customer_id = o.customer_id
LEFT JOIN reviews r ON c.customer_id = r.customer_id
GROUP BY c.customer_id, c.name, c.email, c.signup_date
"""

# Real-time dashboard query
realtime_metrics = """
SELECT 
    DATE_TRUNC('hour', event_timestamp) as hour,
    event_type,
    COUNT(*) as event_count,
    COUNT(DISTINCT user_id) as unique_users,
    SUM(CASE WHEN event_type = 'purchase' THEN revenue ELSE 0 END) as hourly_revenue
FROM clickstream_events
WHERE event_timestamp >= CURRENT_TIMESTAMP - INTERVAL '24' HOUR
GROUP BY DATE_TRUNC('hour', event_timestamp), event_type
ORDER BY hour DESC
"""
```

---

### Use Case 3: Financial Services Compliance

```
SCENARIO: Bank with Regulatory Requirements (SOX, PCI-DSS)

Requirements:
├─ Audit all data access
├─ Encrypt sensitive data (SSN, account numbers)
├─ Data retention (7 years for transactions)
├─ Immutable audit trail
└─ Separation of duties

Implementation:
```

```bash
#!/bin/bash
# Financial services data lake setup

# 1. Enable S3 Object Lock (immutability for compliance)
aws s3api put-object-lock-configuration \
  --bucket financial-data-lake \
  --object-lock-configuration '{
    "ObjectLockEnabled": "Enabled",
    "Rule": {
      "DefaultRetention": {
        "Mode": "COMPLIANCE",
        "Years": 7
      }
    }
  }'

# 2. Enable versioning (required for Object Lock)
aws s3api put-bucket-versioning \
  --bucket financial-data-lake \
  --versioning-configuration Status=Enabled

# 3. Enable server-side encryption with KMS
aws s3api put-bucket-encryption \
  --bucket financial-data-lake \
  --server-side-encryption-configuration '{
    "Rules": [{
      "ApplyServerSideEncryptionByDefault": {
        "SSEAlgorithm": "aws:kms",
        "KMSMasterKeyID": "arn:aws:kms:region:account:key/compliance-key"
      }
    }]
  }'

# 4. Create LF-Tags for compliance tracking
aws lakeformation create-lf-tag \
  --tag-key DataClassification \
  --tag-values "Public" "Internal" "Confidential" "Restricted"

aws lakeformation create-lf-tag \
  --tag-key ComplianceFramework \
  --tag-values "SOX" "PCI-DSS" "GLBA" "None"

aws lakeformation create-lf-tag \
  --tag-key RetentionYears \
  --tag-values "1" "3" "7" "Permanent"

# 5. Tag financial transactions table
aws lakeformation add-lf-tags-to-resource \
  --resource '{"Table": {"DatabaseName": "financial_db", "Name": "transactions"}}' \
  --lf-tags '[
    {"TagKey": "DataClassification", "TagValues": ["Restricted"]},
    {"TagKey": "ComplianceFramework", "TagValues": ["SOX", "PCI-DSS"]},
    {"TagKey": "RetentionYears", "TagValues": ["7"]}
  ]'

# 6. Grant permissions with audit trail
aws lakeformation grant-permissions \
  --principal DataLakePrincipalIdentifier=arn:aws:iam::ACCOUNT:role/Auditors \
  --permissions SELECT DESCRIBE \
  --resource '{"Table": {"DatabaseName": "financial_db", "Name": "transactions"}}' \
  --permissions-with-grant-option SELECT  # Auditors can grant to others

# 7. Create audit query view
cat > audit_view.sql <<EOF
CREATE OR REPLACE VIEW audit_access_log AS
SELECT 
    useridentity.principalid as user,
    eventname as action,
    requestparameters.databasename as database,
    requestparameters.name as table,
    eventtime as access_time,
    sourceipaddress as source_ip,
    useragent
FROM cloudtrail_logs
WHERE eventname IN (
    'GetTable', 'GetDatabase', 'BatchGetPartition',
    'GetPartitions', 'StartQueryExecution'
)
AND requestparameters.databasename = 'financial_db'
ORDER BY eventtime DESC;
EOF

# 8. Set up compliance monitoring alerts
aws cloudwatch put-metric-alarm \
  --alarm-name UnauthorizedDataAccess \
  --alarm-description "Alert on failed Lake Formation access attempts" \
  --metric-name UnauthorizedAPICallsCount \
  --namespace CloudTrailMetrics \
  --statistic Sum \
  --period 300 \
  --evaluation-periods 1 \
  --threshold 5 \
  --comparison-operator GreaterThanThreshold \
  --alarm-actions arn:aws:sns:region:account:security-alerts
```

---

## 🎓 KEY TAKEAWAYS & SUMMARY

### When to Use Lake Formation

✅ **USE Lake Formation when:**
- Building a centralized data lake (S3 + analytics)
- Need fine-grained access control (column/row-level)
- Multiple teams need different views of same data
- Compliance requirements (HIPAA, SOX, GDPR)
- Want simplified permission management
- Need audit trails for data access
- Integrating multiple data sources
- Want to query data with Athena/Redshift/EMR

❌ **Don't use Lake Formation when:**
- Simple S3 storage (no complex permissions needed)
- Real-time transactional database (use RDS/DynamoDB)
- Small datasets (<100 GB)
- Single-user access only
- No governance requirements

---

### Lake Formation vs Alternatives

```
LAKE FORMATION vs S3 + GLUE:
├─ Lake Formation = S3 + Glue + Security + Governance
├─ Use Lake Formation for: Enterprise data lakes
└─ Use S3 + Glue for: Simple data pipelines

LAKE FORMATION vs REDSHIFT:
├─ Lake Formation = Storage + Catalog (query with Athena)
├─ Redshift = Data Warehouse (fast queries, BI workloads)
├─ Use both: Redshift Spectrum queries Lake Formation!
└─ Pattern: Hot data in Redshift, cold data in Lake Formation

LAKE FORMATION vs DATA WAREHOUSE:
├─ Lake Formation: Schema-on-read, all data types, cheap
├─ Data Warehouse: Schema-on-write, structured, expensive
└─ Modern pattern: Lake Formation + Redshift Spectrum
```

---

### Architecture Patterns

**Pattern 1: Medallion Architecture**
```
Bronze (Raw) → Silver (Cleaned) → Gold (Curated)
    S3            Glue ETL           Analytics
```

**Pattern 2: Lambda Architecture**
```
Batch: Lake Formation (historical data)
  +
Stream: Kinesis → Lake Formation (recent data)
  =
Complete view for analytics
```

**Pattern 3: Data Mesh**
```
Team A's Lake ←→ Central Catalog ←→ Team B's Lake
(Cross-account sharing via Lake Formation)
```

---

### Cost Summary

```
LAKE FORMATION PRICING:
├─ Lake Formation service: FREE
├─ S3 storage: ~$0.023/GB/month
├─ Glue crawler: $0.44/DPU-hour
├─ Glue ETL: $0.44/DPU-hour
├─ Athena queries: $5/TB scanned
└─ Data transfer: $0.09/GB (out to internet)

COST OPTIMIZATION:
├─ Use Parquet: 10x smaller = 10x cheaper queries
├─ Partition data: Scan less data
├─ Lifecycle policies: Archive to Glacier
└─ Use LF-Tags: Reduce management overhead
```

---

## 🎉 CONGRATULATIONS!

You now have **complete Lake Formation expertise**:

✅ **Fundamentals:** Data lake concepts, Lake Formation architecture
✅ **Setup:** Console & CLI cluster creation, blueprints
✅ **Security:** Row/column filtering, LF-Tags, cross-account
✅ **Data Ingestion:** Blueprints, Glue ETL, streaming
✅ **Analytics:** Athena, Redshift Spectrum, EMR, SageMaker
✅ **Operations:** Monitoring, troubleshooting, best practices
✅ **Real-World:** Healthcare, e-commerce, financial use cases

**Next Steps:**
1. Build your own data lake (use the hands-on labs!)
2. Practice with sample datasets
3. Explore advanced features (Governed Tables, Transactions)
4. Prepare for AWS Data Analytics certification
5. Implement in production environments

**You're now ready to design and implement enterprise data lakes with AWS Lake Formation!** 🚀📊
