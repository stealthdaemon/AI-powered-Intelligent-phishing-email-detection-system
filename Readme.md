# Intelligent Phishing Email Detection System

The application analyzes all parts of an email to detect phishing indicators, classifying emails as either phishing or legitimate.

![The simple user interface](/Picture1.png "User interface")

Leveraging LLMs for phishing email detection offers a more effective approach than traditional ML algorithms, which rely on manually engineered features.

The app decodes every component of the email, including the headers and all base64-encoded MIME binary attachments in order to analyze them individually and classify the email accurately.

![Correctly classified Legitimate email](/Picture3.png "legitimate email")

## To run application

1. Open command prompt or terminal
2. Change directory - `cd ./system/phishingdetection`
3. Start the server - Run the following command `python manage.py runserver`
4. Open browser and type the link - should be _127.0.0.1:8000/detect_
5. Download any email in _.eml_ or _.txt_ format and test the application

## For OCR
Install tesseract and set the path for OCR in process_email.py in the decode_image function
`pytesseract.pytesseract.tesseract_cmd = r'your-installation-path'`

## OpenAI API KEY

You can easily set up your own openAI api key.
When you have it, update the api-key variable in `system\phishingdetection\detect\detection.py`.
You can reach out to me for help at `stealthingdemon@gmail.com`. 
LOL dont be intimidated by the email, its just a pseudonym. I promise i'm much friendlier than it sounds.

## Notes

*Note:* _The emails used in the experiment were excluded from the final submission as a security precaution, because some contained potentially harmful contents, such as phishing emails and harmful encoded binary files. However, the results of the experiment are stored in JSON files in the experiment folder._

_If you are running this locally, refer to the *requirements.txt* file for a complete list of Python packages used in this project._
