import email
import base64
import random
import shutil
from email import policy
from email.parser import BytesParser
import re
import pytesseract
from bs4 import BeautifulSoup
import json
from io import BytesIO
from PIL import Image
import os
import PyPDF2
import mimetypes

# detect language
# from langdetect import detect, DetectorFactory
# from langdetect.lang_detect_exception import LangDetectException

# words
# from nltk.corpus import words

# Download the word list if not already available
# nltk.download('words')
# word_list = set(words.words())

# Preprocess emails before analysis


def extract_headers(input_email):
    """ Function to parse the email and extract headers """

    # use msg = email.message_from_string(input_email) for string

    msg = BytesParser(policy=policy.default).parsebytes(input_email)
    email_headers = {
        'From': msg.get('From'),
        'To': msg.get('To'),
        'Subject': msg.get('Subject'),
        'Date': msg.get('Date'),
        'Return-Path': msg.get('Return-Path'),
        'Reply-To': msg.get('Reply-To'),
        'Received': msg.get_all('Received'),
        'Message-ID': msg.get('Message-ID'),
        'X-Mailer': msg.get('X-Mailer'),
        'X-Spam-Status': msg.get('X-Spam-Status'),
        'X-Spam-Flag': msg.get('X-Spam-Flag'),
        'Content-Type': msg.get('Content-Type'),
        'Authentication-Results': msg.get('Authentication-Results'),
        'DKIM-Signature': msg.get('DKIM-Signature'),
    }
    return email_headers


def decode_base64(email_content):
    """ Function to decode Base64 encoded content """
    try:
        # return base64.b64decode(email_content).decode('utf-8', errors='ignore')
        return base64.b64decode(email_content)
    except Exception as e:
        print(f"Error decoding Base64: {str(e)}")
        return None


def decode_image(image_data, image_type):
    # Check if the provided image type is valid
    if not image_type.startswith("image/"):
        return None

    try:
        print("Extracting texts from image using OCR...")
        # set the path for OCR
        pytesseract.pytesseract.tesseract_cmd = r'C:\Program Files\Tesseract-OCR\tesseract.exe'

        # process the decoded image data
        processed_image = Image.open(BytesIO(image_data))
        # processed_image.verify()  # Verify that the file is a valid image
        # show image
        # processed_image.show()
        # processed_image.save(fp=r"C:\Users\Daemon\Downloads\public_phishing\phishing3\img.png")

        # Extract text from the image using OCR
        image_text = pytesseract.image_to_string(processed_image)
        return image_text if image_text else None

    except Exception as e:
        # Return None if any exception occurs
        return None


def extract_texts(text_data, text_mimetype, charset):
    """ Function to extract text from decoded base64 text/ or json types"""
    print("Extracting texts...")
    if not charset:
        charset = 'utf-8'
    text_content = text_data.decode(charset)
    if text_mimetype == 'text/html':
        text_content = chunk_html(text_content)
        return ''.join(text_content)
    return text_content


def extract_pdf(pdf_data, extract):
    """ Function to extract pdf texts from decoded base64"""
    # Load the PDF from the decoded data
    pdf_text = ""
    try:
        print("Extracting text from PDF...")
        pdf_reader = PyPDF2.PdfReader(BytesIO(pdf_data))

        if extract is False:
            return pdf_reader.is_encrypted

        for page_num in range(len(pdf_reader.pages)):
            try:
                page = pdf_reader.pages[page_num]
                pdf_text += page.extract_text()
            except Exception as e:
                print(f"Error extracting text from page {page_num}: {e}")
    except Exception as e:
        print(f"Error reading the PDF: {e}")
    return pdf_text


def validate_decode(data, mime_type, charset):
    """Validate decoded data"""
    if not charset:
        charset = 'utf-8'

    # For text MIME types
    if mime_type.startswith("text/"):
        try:
            decoded_text = data.decode(charset)
            # print("Decoded text content:", decoded_text[:200])  # Show a snippet
            return 'valid'  # Matches expected MIME type
        except UnicodeDecodeError:
            return "invalid"  # Decoded, but unsure if valid for MIME type

    # For JSON data
    elif mime_type == "application/json":
        try:
            json_data = json.loads(data.decode(charset))
            # print("Decoded JSON content:", json_data)
            return 'valid'  # Matches expected MIME type
        except (UnicodeDecodeError, json.JSONDecodeError):
            return "invalid"  # Decoded, but unsure if valid for MIME type

    # For images
    elif mime_type.startswith("image/"):
        try:
            image = Image.open(BytesIO(data))
            # Verify if it's a valid image
            image.verify()
            return "valid"  # Matches expected MIME type
        # except (IOError, ValueError):
        except Exception as error:
            print(str(error))
            return "invalid"  # Decoded, but unsure if valid for MIME type

    # For PDF
    elif mime_type == "application/pdf":
        if data.startswith(b"%PDF"):
            return "valid"  # Matches expected MIME type
        else:
            return "invalid"  # Decoded, but unsure if valid for MIME type

    # For ZIP files
    elif mime_type == "application/zip":
        if data.startswith(b"PK"):
            return "valid"  # Matches expected MIME type
        else:
            return "invalid"  # Decoded, but unsure if valid for MIME type

    # Generic binary data check
    elif mime_type == "application/octet-stream":
        if data.startswith(b"PK"):
            return "valid"  # Matches expected MIME type
        else:
            return "uncertain"  # Decoded, but uncertain

    else:
        return "uncertain"  # Decoded, but unsure if valid for MIME type


def chunk_text(text, chunk_size=1500):
    """ Function to chunk the text content into smaller parts """
    chunks = [text[i:i + chunk_size] for i in range(0, len(text), chunk_size)]
    return chunks


def chunk_html(content, chunk_size=1000):
    """ Function to chunk the HTML content into smaller parts"""
    soup = BeautifulSoup(content, 'html.parser')
    # Extract all text inside HTML body, while keeping structure
    text = soup.get_text(separator="\n", strip=True) + extract_tags(content)
    chunks = [text[i:i + chunk_size] for i in range(0, len(text), chunk_size)]
    return chunks


def extract_with_tags(element):
    """ # Function to retain specific tags and attributes in the text """
    if element.name == 'a' and 'href' in element.attrs:
        return f'\n<a href="{element["href"]}">{element.get_text()}</a>'
    elif element.name == 'form':
        return f'\n' + str(element)  # Retain <form> tag and its children
    elif element.name == 'script':
        return f'\n' + str(element)  # Retain <script> tag content
    else:
        return element.get_text(separator="\n", strip=True)


def extract_tags(content):
    """ Function to chunk the HTML content into smaller parts,
    preserving <a> tags with href, <form> tag, and <script> tags. """
    soup = BeautifulSoup(content, 'html.parser')
    # Extract text while preserving structure of certain tags
    elements = soup.find_all(['a', 'form', 'script'])  # Finds the specified tags and text nodes
    extracted_text = "".join(extract_with_tags(el) for el in elements)
    return extracted_text


def get_filename(directory, filename, content_type):

    extension = mimetypes.guess_extension(content_type)

    if content_type.startswith('image/'):
        if filename is None:
            filename = "image" + extension
    else:
        if filename is None:
            filename = "file" + extension

    if not os.path.exists(os.path.join(directory, filename)):
        return filename

    while os.path.exists(os.path.join(directory, filename)):
        base_name, extension = os.path.splitext(filename)
        filename = base_name + str(random.randint(1, 100)) + extension

    return filename


def extract_email_content(raw_email, folder_name):
    """ Function to extract and decode email parts (Texts, HTML, Base64) """

    # use msg = email.message_from_string(raw_email) for email from string

    msg = BytesParser(policy=policy.default).parsebytes(raw_email)

    # Collect text and HTML parts
    text_content = ""
    html_content = ""
    base64_parts_info = []
    base64_parts = []

    folder_name = folder_name.replace('.', '')
    file_path = "./detect/decoded_contents/" + folder_name
    if os.path.exists(file_path):
        shutil.rmtree(file_path)

    for part in msg.walk():  # use .__iter__() for email from string
        content_type = part.get_content_type()
        content_transfer_encoding = part.get('Content-Transfer-Encoding')

        # Process plain text content
        if content_type == 'text/plain' and content_transfer_encoding != 'base64':
            text_content += part.get_payload(decode=True).decode(part.get_content_charset() or 'utf-8', errors='ignore').strip()

        # Process HTML content
        elif content_type == 'text/html' and content_transfer_encoding != 'base64':
            html_content += part.get_payload(decode=True).decode(part.get_content_charset() or 'utf-8', errors='ignore').strip()

        # Process Base64 encoded parts
        elif content_transfer_encoding == 'base64':
            base64_data = part.get_payload().strip()
            decoded_data = decode_base64(base64_data)
            if decoded_data:
                base64_parts.append(decoded_data)  # add decoded base64 to the list
                base64_parts_info.append({
                    'Content-Type': content_type,
                    'Charset': part.get_content_charset(),
                    'Content-Transfer-Encoding': content_transfer_encoding,
                    'Content-ID': part.get('Content-ID'),
                    'Content-Disposition': part.get_content_disposition(),
                    'name': part.get_filename(),
                    'filename': part.get_filename(),
                    'validate': validate_decode(decoded_data, content_type, part.get_content_charset()),
                    'processed': False,
                })  # add the file information to the list
                if not (content_type.startswith('text/') or content_type == 'application/json'):
                    if base64_parts_info[-1]['validate'] != 'invalid':
                        # create the folder to store decoded base64 files
                        if not os.path.exists(file_path):
                            os.mkdir(file_path)
                        # create the file
                        filename = get_filename(file_path, base64_parts_info[-1]['filename'], content_type)
                        filename = os.path.join(file_path, filename)
                        with open(filename, "wb") as file:
                            file.write(base64_parts[-1])
                        base64_parts_info[-1]['stored_file'] = filename

                        if content_type == 'application/pdf':
                            base64_parts_info[-1]['encrypted'] = extract_pdf(base64_parts[-1], False)

    # Chunk the text content into manageable sections
    text_chunks = chunk_text(text_content)

    # Chunk the HTML content into manageable sections
    html_chunks = chunk_html(html_content)

    return {
        'text_content': {  # 'texts': check_valid_text(text_chunks),
                           # 'language': get_language(text_chunks),
                         'content': text_chunks
                         },
        'html_content': {  # 'texts': check_valid_text(html_chunks),
                           # 'language': get_language(html_chunks),
                         'content': html_chunks
                         },
        'base64_parts_info': base64_parts_info,
        'base64_parts': base64_parts
    }


""" 
def check_valid_text(input_text):
    if input_text:
        word_list = set(words.words())
        # Split the text into words and filter out empty strings
        words_in_text = [word for word in input_text[0].split() if word.isalpha()]
        # Count words that are in the dictionary
        valid_word_count = sum(1 for word in words_in_text if word.lower() in word_list)
        # Consider it coherent if at least 50% of the words are valid dictionary words
        if valid_word_count / max(len(words_in_text), 1) > 0.1:
            return "valid"
        else:
            return "invalid"
    else:
        return "invalid"
"""


""" 
def get_language(input_text):
    # detect language
    DetectorFactory.seed = 0
    if input_text:
        try:
            # Detect language
            lang = detect(input_text[0])
            return lang  # Adjust languages as needed
        except LangDetectException:
            return "unknown"
    else:
        return "unknown"
"""


def process_email(path):
    """Function to read email from a .eml file or a .txt file"""

    try:

        # check the file extension
        if os.path.splitext(os.path.basename(path))[1] not in [".eml", ".txt"]:
            raise Exception("file format not supported. Please upload a .eml or .txt file")

        # read the file
        with open(path, 'rb') as file:
            path_email = file.read()

        # return the processed email
        return {'name': os.path.basename(path),
                'headers': extract_headers(path_email),
                'content': extract_email_content(path_email, os.path.basename(path))
                }

    except Exception as error:
        return f"Invalid input, {str(error)}"


if __name__ == "__main__":
    # Read email from a .eml file or a .txt file
    with open(r'C:\Users\Daemon\Downloads\2.eml', 'rb') as f:
        raw_email = f.read()

    # Extract headers
    headers = extract_headers(raw_email)
    print("Headers:", headers)

    # Extract content (HTML, plain text, Base64)
    content = extract_email_content(raw_email)

    # Display texts, HTML and Base64 parts
    print("\nText Chunks:")
    # print("text: " + content['text_content']['texts'])
    # print("language: " + content['text_content']['language'])
    for text in content['text_content']['content']:
        print(text)

    print("\nHTML Chunks:")
    # print("text: " + content['html_content']['texts'])
    # print("language: " + content['html_content']['language'])
    for chunk in content['html_content']['content']:
        print(chunk)

    # print("\nBase64 Parts:")
    # for base64_part in content['base64_parts']:
    #    print(base64_part)

    for i in range(len(content['base64_parts'])):
        print("\nBase64 Parts Information:")
        print(content['base64_parts_info'][i])

        print("\nBase64 Parts:")
        print(content['base64_parts'][i])

        # print(decode_image(content['base64_parts'][i], content['base64_parts_info'][i]['Content-Type']))