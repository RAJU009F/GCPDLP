#Add
def deidentify_csv(
    project,
    input_csv_file=None,
    output_csv_file=None,
    field_to_be_redacted=None,
    info_types=None,
    regex_pattern=None,
    service_account_path=None,
):
    """Uses the Data Loss Prevention API to deidentify dates in a CSV file by
        pseudorandomly shifting them.
    Args:
        project: The Google Cloud project id to use as a parent resource.
        input_csv_file: The path to the CSV file to deidentify. The first row
            of the file must specify column names, and all other rows must
            contain valid values.
        output_csv_file: The path to save the date-shifted CSV file.
        field_to_be_redacted: The list of (date) fields in the CSV file to redact.
            Example: ['Text']
        info_types: List of Infotypes to Redact
            Example: ['AGE','PASSWORD','FIRST_NAME']
        regex_pattern: String representing the Regex Pattern
    Returns:
        None; the response from the API is printed to the terminal.
    """
    # Import the client library
    import google.cloud.dlp
    import math
    import sys
    import time
    import csv
    import datetime

    # Instantiate a client
    dlp = google.cloud.dlp_v2.DlpServiceClient.from_service_account_json(service_account_path)

    # Convert the project id into a full resource id.
    parent = f"projects/{project}"

    # Convert the field to be redacted to Protobuf type
    def map_fields(field):
        return {"name": field}

    if field_to_be_redacted:
        field_to_be_redacted = list(map(map_fields, field_to_be_redacted))
    else:
        field_to_be_redacted = []

    # Read and parse the CSV file

    f = []
    with open(input_csv_file, "r", encoding="utf8", errors='ignore') as csvfile:
        reader = csv.reader(csvfile,delimiter = "|")
        for row in reader:
            f.append(row)

    num_record = len(f) 
    batch_size = 2000 # batching the request to avoid hitting API limit
    num_batch = math.floor(num_record/batch_size)

    #Helper function for converting CSV rows to Protobuf types
    def map_headers(header):
        return {"name": header}

    def map_data(value):
        return {"string_value": value}

    def map_rows(row):
        return {"values": map(map_data, row)}

     # Write to CSV helper methods

    def write_header(header):
        return header.name

    def write_data(data):
        return data.string_value

    #DLP Configurations
    custom_info_types = [
        {
            "info_type": {"name": "CUSTOM_NAME"},
            "regex": {"pattern": regex_pattern, "group_indexes":[1,2,3]},
            "likelihood": "VERY_LIKELY",
        }
    ]


    # Construct inspect configuration dictionary
    inspect_config = {"custom_info_types": custom_info_types,
                      "info_types": [{"name": info_type} for info_type in info_types]}

    #Construct deidentify configuration dictionary
    deidentify_config = {
        "record_transformations": {
            "field_transformations": [
                {
                    "fields": field_to_be_redacted,
            "info_type_transformations": {
                "transformations": [
                    {
                        "primitive_transformation": {
                        "character_mask_config": {
                            "masking_character": '#',
                        "characters_to_ignore":[
                  {
                    "common_characters_to_ignore":"PUNCTUATION"
                  }
                ]
                            
                        }
                        }
                    }
            ]
        },
                }
            ]
        }
    }


    # Using the helper functions, convert CSV rows to protobuf-compatible
    # dictionaries.

    for i in range(1,len(f),batch_size):
        
        csv_headers = map(map_headers, f[0])
        csv_rows = map(map_rows, f[i:min(i+batch_size,num_record)])

        # Construct the table dict
        table_item = {"table": {"headers": csv_headers, "rows": csv_rows}}

        # Call the API
        response = dlp.deidentify_content(
            parent,
            inspect_config=inspect_config,
            deidentify_config=deidentify_config,
            item=table_item
        )

        # Write results to CSV file
        if i == 1:
            with open(output_csv_file, "w") as csvfile:
                write_file = csv.writer(csvfile, delimiter="|")
                write_file.writerow(map(write_header, response.item.table.headers))
                for row in response.item.table.rows:
                    write_file.writerow(map(write_data, row.values))
        else:
             with open(output_csv_file, "a") as csvfile:
                write_file = csv.writer(csvfile, delimiter="|")
                for row in response.item.table.rows:
                    write_file.writerow(map(write_data, row.values))

        print("Redacted rows from {} to {}".format(i,min(i+batch_size,num_record)))
        time.sleep(0.25)

    print("Successfully saved redacted output to {}".format(output_csv_file))



####################### MODIFY YOUR VARIABLES ##############################################

project='<UPDATE_GCP_PROJECT_NAME>'
info_types=[<"UPDATE_COMMA_SEPARATE_STRING_INFO_TYPES">]
"""EXAMPLE:#############
#################### 
 "CANADA_BANK_ACCOUNT", "CANADA_BC_PHN", "CANADA_DRIVERS_LICENSE_NUMBER", "CANADA_OHIP", "CANADA_PASSPORT", "CANADA_QUEBEC_HIN", "CANADA_SOCIAL_INSURANCE_NUMBER", "EMAIL_ADDRESS", "FEMALE_NAME", "FIRST_NAME", "GENERIC_ID", "LAST_NAME", "LOCATION", "MALE_NAME", "PASSPORT", "PERSON_NAME", "STREET_ADDRESS", "US_ADOPTION_TAXPAYER_IDENTIFICATION_NUMBER", "US_BANK_ROUTING_MICR", "US_DEA_NUMBER", "US_DRIVERS_LICENSE_NUMBER", "US_EMPLOYER_IDENTIFICATION_NUMBER", "US_HEALTHCARE_NPI", "US_INDIVIDUAL_TAXPAYER_IDENTIFICATION_NUMBER", "US_PASSPORT", "US_PREPARER_TAXPAYER_IDENTIFICATION_NUMBER", "US_SOCIAL_SECURITY_NUMBER", "US_STATE", "US_TOLLFREE_PHONE_NUMBER", "US_VEHICLE_IDENTIFICATION_NUMBER" 
#########################
"""

input_csv_file='<UPDATE_LOCAL_CSV_INPUT_FILE>'
output_csv_file='<UPDATE_LOCAL_CSV_OUTPUT_FILE>'
field_to_be_redacted=[<COLUMN_NAME(S)_FROM_CSV_STRUCTURED_FILE_TO_BE_REDACTED>]
regex_pattern="(\d{10})|(\d{3}-\d{3}-\d{3})|(\d{3})|(\d{9})|(\d{3}-\d{3}-\d{4})"
service_account_path="<SERVICE_ACCOUNT_JSON_FILE_LOCAL_PATH>"
###########################################################################################
import datetime
start_time =  datetime.datetime.now()
deidentify_csv(project,input_csv_file,output_csv_file,field_to_be_redacted,info_types,regex_pattern,service_account_path)
end_time = datetime.datetime.now()

print("start time:{},  end time:{},  timetaken:{}".format(start_time,end_time,(end_time-start_time) ))
