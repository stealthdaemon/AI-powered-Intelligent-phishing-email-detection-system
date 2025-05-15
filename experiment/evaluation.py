import matplotlib.pyplot as plt

# for machine learning
from sklearn import metrics

import json

Y = []
Y_pred = []
lscore = 0
pscore = 0
phishingpath = r"phishinganalysis.json"
legitpath = r"legitanalysis.json"

for i in range(0, 300):
    Y.append(1)
for i in range(0, 300):
    Y.append(0)

with open(phishingpath, 'r') as pfile:
    p = pfile.read().strip()
p = json.loads(p)
for key, value in p.items():
    pscore += value['confidence']
    if value['is_phishing'] is True and value['user_feedback'] == 'correct':
        Y_pred.append(1)
    else:
        Y_pred.append(0)

with open(legitpath, 'r') as lfile:
    l = lfile.read().strip()
l = json.loads(l)
for key, value in l.items():
    lscore += value['confidence']
    if value['is_phishing'] is False and value['user_feedback'] == 'correct':
        Y_pred.append(0)
    else:
        Y_pred.append(1)

cm = metrics.confusion_matrix(Y, Y_pred)
TN, FP, FN, TP = cm.ravel()
print(f"TN={TN}, FP={FP}, FN={FN}, TP={TP}")
disp = metrics.ConfusionMatrixDisplay(confusion_matrix=cm)
disp.plot()
plt.show()

print(metrics.accuracy_score(Y, Y_pred))
print(metrics.recall_score(Y, Y_pred))
print(metrics.precision_score(Y, Y_pred))
print(metrics.f1_score(Y, Y_pred))

print('Classification Report for the analysis')
print(metrics.classification_report(Y, Y_pred))

print(f"Average confidence score for phishing emails is {pscore / len(p.keys())}")
print(f"Average confidence score for legitimate emails is {lscore / len(l.keys())}")
