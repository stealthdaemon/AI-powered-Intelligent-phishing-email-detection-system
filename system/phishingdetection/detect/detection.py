from openai import OpenAI
import json
import os
from . import process_email
import shutil

OPENAI_API_KEY = "your-openai-api-key"
client = OpenAI(api_key=OPENAI_API_KEY)


def categorize_confidence(confidence_percentage):
    """Categorizes the confidence percentage into high, medium, or low."""
    if confidence_percentage >= 80:
        return "High"
    elif confidence_percentage >= 50:
        return "Medium"
    else:
        return "Low"


def get_user_feedback(file_key, input_data):
    """Prompts the user for feedback on whether the output was correct."""

    allowed = ['correct', 'wrong']
    if not input_data.lower() in allowed:
        return {'Error': f"Enter either correct or wrong."}

    data = {}
    try:
        with open(f'./detect/analysis.json', 'r') as file:
            json_file = file.read().strip()
            if json_file:
                data = json.loads(json_file)
    except FileNotFoundError as error:
        return {'Error': f"{error}"}

    if file_key in data:
        if data[file_key]['user_feedback'] == 'none':
            data[file_key]['user_feedback'] = input_data.lower()

    # Write the updated data back to file
    try:
        with open(f'./detect/analysis.json', 'w') as file:
            json.dump(data, file, indent=4)
    except Exception as error:
        return {'Error': f"{error}"}

    return {'success': 'Feedback updated successfully.'}


def analyze_part(headers, text_content="", html_content="", base64_contents=[], part_info=[]):
    """ Analyzes a specific part of the email for phishing indicators. """
    prompt = f"""
    Analyze the email thoroughly for potential phishing indicators.
    - Review the headers to ensure they originate from trusted sources.  
    - Check all URLs in the email to confirm they point to legitimate domains. 
    - Avoid classifying the email as phishing based solely on its content unless there are clear 
    inconsistencies in the headers or indications that the links lead to malicious or suspicious domains.
    Entire response should consist of a single JSON object {{}}, and must NOT be wrapped within JSON md markers.
    Response format:
    {{
        "is_phishing": true or false,
        "confidence": A numeric confidence level from 0 to 100 indicating the likelihood of phishing or not,
        "reasoning": "Detailed explanation. Keep the response in sentence form, direct, without additional commentary, and avoid including long URLs."
    }}
    """
    if headers:
        prompt += f"\nEmail Headers:\n"
        for key, value in headers.items():
            if value is not None:
                prompt += f"{key}: {value}\n"

    if text_content:
        prompt += f"\ntext/plain\nText Content: {text_content}\n"

    if html_content:
        prompt += f"\ntext/html\nHTML Content: {html_content}\n"

    if base64_contents and part_info:
        for content, part_information in zip(base64_contents, part_info):
            prompt += f"\n{part_information}\nContent: {content}\n"
    try:
        response = client.chat.completions.create(
            model="gpt-4o",
            messages=[
                {"role": "system", "content": "You are an email security expert specialized in phishing detection."},
                {"role": "user", "content": prompt}
            ],
            temperature=0.3,  # randomness - factual accuracy and consistent responses
            max_tokens=300,  # max number of tokens for each response
            top_p=1.0  # nucleus sampling - Controls diversity in token selection
        )

        analysis = response.choices[0].message.content

        # Check to see if json response terminates correctly
        if not analysis.endswith('}'):

            # find the last period(.) to terminate json response
            last_period_index = analysis.rfind(".")

            # truncate the last period then terminate the json response correctly
            analysis = analysis[:last_period_index + 1].strip() + "\"}"

        analysis_json = json.loads(analysis)
        return analysis_json

    except Exception as e:
        return {
            "error": str(e),
            "is_phishing": None,
            "confidence": 0,
            "reasoning": f"An error occurred while analyzing the part. Please check the input and try again."
        }


def analyze_email(email_parts, path):
    """Analyze each part of the email for phishing indicators"""

    try:
        headers = email_parts['headers']
        text_content = ''.join(email_parts['content']['text_content']['content'])
        html_content = ''.join(email_parts['content']['html_content']['content'])
        base64_content = []
        part_details = []
        base64_parts = email_parts['content']['base64_parts']
        base64_parts_info = email_parts['content']['base64_parts_info']

        # Check to see if the email contains any base64 content-transfer-encoding, analyze each
        if base64_parts and base64_parts_info:
            i = 0

            # iterate through each base64 content
            for part, part_info in zip(base64_parts, base64_parts_info):

                if part_info['validate'] == "valid":  # check if the decoded data is valid

                    if part_info['Content-Type'].startswith("image/"):
                        print("Decoding image...")
                        info = "TEXT/PLAIN EXTRACTED FROM IMAGE (IGNORE SPELLING IF SCRAMBLED)"
                        image_content = process_email.decode_image(part, part_info['Content-Type'])
                        if image_content:
                            base64_content.append(image_content)
                            part_details.append(info)
                            base64_parts_info[i]['processed'] = True

                    elif part_info['Content-Type'].startswith("text/") or part_info['Content-Type'] == 'application/json':
                        print("Decoding texts...")
                        info = f"{part_info['Content-Type']}"
                        text_content = process_email.extract_texts(part, part_info['Content-Type'], part_info['Charset'])
                        if text_content:
                            base64_content.append(text_content)
                            part_details.append(info)
                            base64_parts_info[i]['processed'] = True

                    elif part_info['Content-Type'] == "application/pdf":
                        print("Decoding PDF...")
                        info = f"TEXT EXTRACTED FROM {part_info['Content-Type']} (IGNORE SPELLING IF SCRAMBLED)"
                        pdf_content = process_email.extract_pdf(part, True)
                        if pdf_content:
                            base64_content.append(pdf_content)
                            part_details.append(info)
                            base64_parts_info[i]['processed'] = True
                i = i + 1

        # analyze email contents
        summary = analyze_part(headers=headers,
                               text_content=text_content,
                               html_content=html_content,
                               base64_contents=base64_content,
                               part_info=part_details)

        confidence_category = categorize_confidence(summary['confidence'])

        summary['confidence_category'] = confidence_category
        summary['user_feedback'] = 'none'  # Initialize with "none" as default feedback

        if base64_parts_info:
            summary['base64_contents'] = []
            for data in base64_parts_info:
                summary['base64_contents'].append(data)

        final_result = {
            email_parts['name']: summary
        }
    
        return final_result

    except Exception as error:
        return f"{error}"


def store_result(dict_file, filename, path):
    # add to json file
    data = {}
    try:
        with open(f'./detect/analysis.json', 'r') as file:
            json_file = file.read().strip()
            if json_file:
                data = json.loads(json_file)
    except FileNotFoundError:
        data = {}  # If the file doesn't exist, start with an empty dict

    if filename not in data.keys():
        # Append or merge the new data
        data.update(dict_file)
    else:
        # if the filename exist, overwrite the existing file
        data[filename] = dict_file[filename]

    # move email to processed folder
    if dict_file[filename]['is_phishing'] is True:
        shutil.move(path, os.path.join(f'./detect/processed_emails/phishing', filename))
    elif dict_file[filename]['is_phishing'] is False:
        shutil.move(path, os.path.join(f'./detect/processed_emails/ham', filename))
    else:
        shutil.move(path, os.path.join(f'./detect/processed_emails/uncertain', filename))

    # Write the updated data back to file
    with open(f'./detect/analysis.json', 'w') as file:
        json.dump(data, file, indent=4)


def main(path):
    try:
        # get email from the specified file path
        # print("Disclaimer: Please ensure all sensitive information, like passwords, login credentials, and credit card details, are removed before uploading emails to the phishing detection system.\n")
        # path = input("Please enter the email file path: ")
        path_feedback = process_email.process_email(path)
        if isinstance(path_feedback, str):
            if path_feedback.startswith("Invalid"):
                raise Exception(path_feedback)


        print("Analyzing email...")

        email_parts = path_feedback
        filename = email_parts['name']

        # Run the analysis
        phishing_result = analyze_email(email_parts, path)

        if not isinstance(phishing_result, dict):
            raise Exception(phishing_result)

        # Display the result
        # print("\nAnalysis :")
        # print(json.dumps(phishing_result, indent=4))

        store_result(phishing_result, filename, path)

        return phishing_result

    except Exception as error:
        # print(f"{str(error)}")
        return {"Error": f"{error}"}


# Run the main function
if __name__ == "__main__":
    pass
    # main()
