import re
import csv

###########################################################

def get_ip_count(filename):
    ip_pattern = r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"
    with open(filename, "r") as file1, open("log_analysis_result1.csv", "w", newline='') as file2:
        output = {}
        data = file1.read() 
        result = re.findall(ip_pattern, data)
        for ip in result:
            if ip in output:
                output[ip] += 1
            else:
                output[ip] = 1
        writer_obj = csv.DictWriter(file2, ["IP Address", "Request Count"])
        writer_obj.writeheader()
        for ip in output:
            writer_obj.writerow({"IP Address": ip, "Request Count":output[ip]})

    return output

##########################################################

def get_frequent_endpoint(filename):
    endpoint_pattern = r"/[a-z]+"
    with open(filename, "r") as file1, open("log_analysis_result2.csv", "w", newline='') as file2:
        output = {}
        data = file1.read()
        endpoints = re.findall(endpoint_pattern, data)
        for endpoint in endpoints:
            if endpoint in output:
                output[endpoint] += 1
            else:
                output[endpoint] = 1
        
        max = 0
        key = None
        for endpoint in output:
            if output[endpoint] > max:
                max = output[endpoint]
                key = endpoint
        writer_obj = csv.DictWriter(file2, ["Endpoint", "Access Count"])
        writer_obj.writeheader()
        writer_obj.writerow({"Endpoint" : key, "Access Count" : max})

    return {key: max}

#################################################################

def get_suspicious_ip_count(filename):
    with open(filename, "r") as file1, open("log_analysis_result3.csv", "w", newline='') as file2:
        output = {}
        ip_pattern = r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"
        for line in file1:
            if "Invalid credentials" in line:
                match = re.findall(ip_pattern, line)[0]
                if match in output:
                    output[match] += 1
                else:
                    output[match] = 1
        writer_obj = csv.DictWriter(file2, ["IP Address", "Failed Login Count"])
        writer_obj.writeheader()
        for ip in output:
            writer_obj.writerow({"IP Address": ip, "Failed Login Count":output[ip]})

    return output

################################################################

def get_log_analysis(filename):
    print(get_ip_count(filename))
    print(get_frequent_endpoint(filename))
    print(get_suspicious_ip_count(filename))


get_log_analysis("task.log")

##################################################################