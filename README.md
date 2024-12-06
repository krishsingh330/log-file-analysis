# log-file-analysis
This repository contains Python scripts (main.py & streamlit_app.py) designed to analyze HTTP log files. The analysis includes insights such as request counts per IP, accessed endpoints, suspicious activities, and more.The main.py script is intended for execution in a Python environment (IDLE), fulfilling all the requirements of the assignment. The streamlit_app.py script, on the other hand, is an additional feature that provides an interactive web application for enhanced analysis, which was not part of the assignment requirements. Both scripts are accompanied by sample log files for testing purposes.

---

## **Features**  

### **1. Command-Line Analysis with `main.py`**  
- Parses HTTP log files and converts them into a structured DataFrame.  
- Performs the following analyses:  
  - **Requests per IP Address:** Count of requests from each IP.  
  - **Most Accessed Endpoints:** Frequently visited URLs.  
  - **Suspicious Activity Detection:** Identifies failed login attempts (HTTP 401).  
- Saves the analysis results to a single CSV file.  

### **2. Web-Based Analysis with `streamlit_app.py`**  
- Interactive log file analysis using Streamlit.  
- Key features:  
  - Upload a log file and analyze data in real-time.  
  - Visualize results with pie charts and bar charts.  
  - Multiple analysis options:
    - Requests per IP Address  
    - Accessed Endpoints  
    - Suspicious Activity  
    - Status Code Distribution  
    - HTTP Method Usage  
    - Timezone and URL Reports  
- Select top values (e.g., Top 5, Top 10) for detailed insights.  

---

## **Setup Instructions**  

### **1. Clone the Repository**  
```bash
git clone https://github.com/<your-username>/log-file-analysis.git
cd log-file-analysis
```
### **2. Install Dependencies**
Ensure you have Python 3.8+ installed. Then, install the required libraries:
```
pip install -r requirements.txt
```
### **3. Folder Structure**
```
log-file-analysis/
│
├── main.py
├── streamlit_app.py           
├── sample_log_files/          # Folder containing sample log files
├── requirements.txt
└── README.md
```
---
## **Usage**
### **1. Command-Line Utility (main.py)**
#### 1.  Place your log file in the project directory or specify its path.
#### 2.  Run the script:**
```bash
python main.py
```
#### 3.  The script processes the log file (sample.log by default) and generates a CSV report (log_analysis_results.csv).
### **2. Web Application (streamlit_app.py)**
#### 1.  Run the Streamlit app:
```bash
streamlit run streamlit_app.py
```
#### 2.  Use the browser interface to:
- Upload your log file.
- View and analyze extracted data.
- Visualize results with charts.
#### 3.  Access your analysis directly on the browser!
#### 4.  Download required table and graph by click in download  symbol

---

## **Sample Log Files**
- A folder named sample_logs contains example log files for testing.
- To test:
  -  Upload the sample file in the Streamlit app.
  -  Or specify the sample file's path in main.py.

---
## **Requirements**
-  Python 3.8+
-  Required libraries for main.py (install via requirements.txt):
    - pandas
    - numpy
    - tqdm
  
-  Required libraries for streamlit_app.py (install via requirements.txt):
    -  pandas
    -  numpy
    -  plotly.express
    -  streamlit
  

---

## **Contact**
Feel free to reach out for any queries or suggestions:

-  Email: krishsingh330@gmail.com
-  LinkedIn: Krishna Singh
-  GitHub: krishsingh330

