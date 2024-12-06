import streamlit as st
import pandas as pd
import numpy as np
import plotly.express as px

# Function for Select Box
def choice(max_row, id,default_value=2):
    option = st.selectbox(
        "Select any one option:",
        ("Top 1", "Top 5", "Top 10", "All Values"),
        placeholder="Top 10", index=default_value, key=id
    )
    if option == "Top 1":
        option = 1
    elif option == "Top 5":
        option = 5
    elif option == "Top 10":
        option = 10
    else:
        option = max_row
    return option

# Function to process the uploaded file
def process_log_file(file_name):
    row_count = 0
    data_rows = []

    try:
        file_content = file_name.read().decode("utf-8")
        for line in file_content.splitlines():
            parts = line.split(" ", 10)

            if len(parts) < 9:
                continue

            ip_address = parts[0]
            time_stamp = parts[3].strip("[")
            time_zone = parts[4].strip("]")
            method = parts[5].strip('"')
            url = parts[6]
            http_protocol = parts[7].strip('"')
            status = parts[8]
            size = parts[9].strip("\n") if len(parts) > 9 else np.nan
            message = parts[10].strip("\n").strip('"').strip('"') if len(parts) > 10 else np.nan

            data_rows.append((ip_address, time_stamp, time_zone, method, url, http_protocol, status, size, message))
            row_count += 1

        data = pd.DataFrame(data_rows, columns=["IP_address", "time_stamp", "time_zone", "methods", "url", "http_protocols", "status", "size", "message"])
        return data

    except Exception as e:
        st.error(f"An error occurred while processing the file: {e}")
        return None

# Function to plot pie chart
def plot_pie_chart(data, values_col, names_col, title, max_values=10):
    fig = px.pie(data.head(max_values), values=values_col, names=names_col, color_discrete_sequence=px.colors.sequential.RdBu)
    st.write(title)
    st.plotly_chart(fig, use_container_width=True)

# Function to plot bar chart
def plot_bar_chart(data, y_col, x_col, title, max_values=10):
    fig = px.bar(data.head(max_values), y=y_col, x=x_col, color_discrete_sequence=px.colors.sequential.RdBu)
    st.write(title)
    st.plotly_chart(fig, use_container_width=True)

# Function to display the top n values in a table
def display_top_table(data, max_values):
    st.write("Data in Table Format")
    st.write(data.head(max_values))
    
# Function to Contact Me
@st.dialog("Contact Me")
def show_contact_details():
    col1,col2,col3,col4=st.columns(4,vertical_alignment='center')
    with col1:
        st.link_button("Call", "tel:+919883357330",icon="📞")
    with col2:
        st.link_button("Email", "mailto:krishsingh330@gmail.com",icon="✉️")
        
    with col3:
        st.link_button("LinkidIn", "https://www.linkedin.com/in/krishna-singh-5b3b67124/")
    with col4:
        st.link_button("GitHub", "https://github.com/krishsingh330")

# Main Streamlit UI and logic
def main():
    #Sidebar Component
    st.sidebar.header(":material/terminal: LOG FILE ANALYSIS")
    file_name = st.sidebar.file_uploader("Upload a log file")
    st.sidebar.text("Made with ♥️ by Krishna")
    
    # Main Page Component
    col1, col2 = st.columns([3, 1],vertical_alignment="bottom")
    with col1:
        st.header(":material/table_chart_view: ANALYSIS REPORT")
    with col2:
        if st.button("Contact Me"):
            show_contact_details()
        
    
    

    if file_name:
        data = process_log_file(file_name)
        if data is not None:
            st.subheader("Extracted Data")
            st.write(data)

            st.subheader("Request Per IP")
            option_1 = choice(len(data), "Request Per IP",3)
            requests_per_ip_data = data.groupby("IP_address").size().reset_index(name="Request Count").sort_values(by="Request Count", ascending=False).reset_index(drop=True)
            col1, col2 = st.columns([2, 2])

            with col1:
                display_top_table(requests_per_ip_data, option_1)
            with col2:
                if option_1 > 10:
                    option_1 = 20
                    st.write("Showing Top 20 Values for Better Chart Clarity")
                plot_pie_chart(requests_per_ip_data, 'Request Count', 'IP_address', f"Top {option_1} IP Request Count", option_1)

            st.subheader("Accessed Endpoint")
            option_2 = choice(len(data), "Accessed Endpoint",0)
            access_endpoint = data.groupby("url").size().reset_index(name="Access Count").sort_values(by="Access Count", ascending=False).reset_index(drop=True)
            col1, col2 = st.columns([2, 2])

            with col1:
                display_top_table(access_endpoint, option_2)
            with col2:
                if option_2 > 10:
                    option_2 = 10
                    st.write("Showing Top 10 Values for Better Chart Clarity")
                plot_bar_chart(access_endpoint, 'Access Count', 'url', f"Top {option_2} Accessed Endpoints", option_2)

            # Detecting Suspicious Activity
            st.subheader("Detecting Suspicious Activity")
            attempts = st.number_input("Flagging IP Threshold Attempts", value=10, placeholder="Threshold Attempt Number ...")
            st.write("Flagging IP Threshold Attempts ", attempts)
            

            suspicious_activity= data[(data["status"] == "401") | (data["message"] == "Invalid credentials")]
            suspicious_activity = suspicious_activity.groupby("IP_address").size().reset_index(name="Count")
            suspicious_activity = suspicious_activity.sort_values(by="Count", ascending=False).reset_index(drop=True)
            suspicious_activity = suspicious_activity[suspicious_activity["Count"] > attempts]

            if len(suspicious_activity) == 0:
                st.write(":green[No Suspicious Activity Detected]")
            else:
                st.write(":red[Suspicious Activity Detected]")
                option_3 = choice(len(data), "Detect Suspicious Activity",3)
                col1, col2 = st.columns([2, 2])
                with col1:
                    display_top_table(suspicious_activity, option_3)
                with col2:
                    if option_3 > 10:
                        option_3 = 10
                        st.write("Showing Top 10 Suspicious Activity for Better Chart Clarity")
                    plot_bar_chart(suspicious_activity, 'Count', 'IP_address', f"Top {option_3} Suspicious IP Count", option_3)

            # URL Report
            st.subheader("URL Report")
            option_4 = choice(len(data), "URL Report")
            get_url_count = data.groupby("url").size().reset_index(name="Count").sort_values(by="Count", ascending=False).reset_index(drop=True)
            col1, col2 = st.columns([2, 2])

            with col1:
                display_top_table(get_url_count, option_4)
            with col2:
                if option_4 > 10:
                    option_4 = 10
                    st.write("Showing Top 10 URL Report for Better Chart Clarity")
                plot_bar_chart(get_url_count, 'Count', 'url', f"Top {option_4} URL Report", option_4)

            # Get Status Report
            st.subheader("Get Status Report")
            option_5 = choice(len(data), "Get Status Report")
            get_status_data = data.groupby("status").size().reset_index(name="Status Count").sort_values(by="Status Count", ascending=False).reset_index(drop=True)
            col1, col2 = st.columns([2, 2])

            with col1:
                display_top_table(get_status_data, option_5)
            with col2:
                if option_5 > 10:
                    option_5 = 10
                    st.write("Showing Top 10 Status Report for Better Chart Clarity")
                plot_pie_chart(get_status_data, 'Status Count', 'status', f"Top {option_5} Status Report", option_5)

            
            # Get Methods Report
            st.subheader("Get Method Report")
            option_6 = choice(len(data), "Get Method Report")
            get_method_data = data.groupby("methods").size().reset_index(name="Methods Count").sort_values(by="Methods Count", ascending=False).reset_index(drop=True)
            col1, col2 = st.columns([2, 2])

            with col1:
                display_top_table(get_method_data, option_6)
            with col2:
                if option_6 > 10:
                    option_6 = 10
                    st.write("Showing Top 10 Methods Report for Better Chart Clarity")
                plot_pie_chart(get_method_data, 'Methods Count', 'methods', f"Top {option_6} Methods Report", option_6)
            
            # Get Timezone Report
            st.subheader("Get Timezone Report")
            option_7 = choice(len(data), "Get Timezone Report")
            get_timezone_data = data.groupby("time_zone").size().reset_index(name="Count").sort_values(by="Count", ascending=False).reset_index(drop=True)
            col1, col2 = st.columns([2, 2])

            with col1:
                display_top_table(get_timezone_data, option_7)
            with col2:
                if option_7 > 10:
                    option_7 = 10
                    st.write("Showing Top 10 Timezone Report for Better Chart Clarity")
                plot_pie_chart(get_timezone_data, 'Count', 'time_zone', f"Top {option_7} Timezone Report", option_7)
if __name__ == "__main__":
    main()
    
    
