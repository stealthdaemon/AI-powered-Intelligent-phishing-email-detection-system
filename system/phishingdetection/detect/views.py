from django.shortcuts import render
from django.http import JsonResponse
from . import detection
import os


def index(request):
    return render(request, 'index.html')


def scan(request):
    data = {}

    if request.method == "POST":
        tmp_file_path = f"./detect/processed_emails/tmp_files/{request.FILES['file'].name}"

        with open(tmp_file_path, "wb") as tmp_file:
            tmp_file.write(request.FILES['file'].read())

        data = detection.main(tmp_file_path)

        if os.path.exists(tmp_file_path):
            os.remove(tmp_file_path)

    if request.headers.get('x-requested-with') == 'XMLHttpRequest':
        return JsonResponse(data)

    return index(request)


def feedback(request):
    data = {}

    if request.method == "POST":
        file_key = request.POST['file_key']
        input_data = request.POST['feedbackInput']
        data = detection.get_user_feedback(file_key, input_data)

    if request.headers.get('x-requested-with') == 'XMLHttpRequest':
        return JsonResponse(data)

    return index(request)
