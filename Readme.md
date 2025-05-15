# Intelligent Phishing Email Detection System

The application analyzes all parts of an email to detect phishing indicators, classifying emails as either phishing or legitimate.

Leveraging LLMs for phishing email detection offers a more effective approach than traditional ML algorithms, which rely on manually engineered features.

## To run application

1. Open command prompt or terminal
2. Change directory - `cd ./system/phishingdetection`
3. Start the server - Run the following command `python manage.py runserver`
4. Open browser and type the link - should be _127.0.0.1:8000/detect_
5. Download any email in _.eml_ or _.txt_ format and test the application

## Notes

*Note:* _The emails used in the experiment were excluded from the final submission as a security precaution, because some contained potentially harmful contents, such as phishing emails and harmful encoded binary files. However, the results of the experiment are stored in JSON files in the experiment folder._

_If you are running this locally, refer to the *requirements.txt* file for a complete list of Python packages used in this project._
