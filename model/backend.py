from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn import metrics
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
from sklearn.model_selection import GridSearchCV
from sklearn.cluster import DBSCAN
from sklearn.preprocessing import StandardScaler

import pandas as pd
import numpy as np


# read in csv data
df = pd.read_csv('data.csv')
df

'''
  Random Forest Prediction
'''
def random_forest_predict():
    # TODO: Replace with actual feature columns and target column
    X = df.drop(['TARGET'], axis=1)
    y= df['TARGET']
    
    # train and test split
    X_train, X_test, y_train, y_test = train_test_split(X,y)

    # hyperparams
    # TODO: Fill in hyperparam values
    param_grid = {
        'n_estimators': [50, 100, 200],
        'max_depth': [None, 10, 20],
        'min_samples_split': [2, 5],
        'min_samples_leaf': [1, 2]
    }

    grid_search = GridSearchCV(
        estimator=RandomForestClassifier(),
        param_grid=param_grid,
        cv=5,
        n_jobs=-1,
        scoring="accuracy"
    )
    # clr = RandomForestClassifier()
    # clr.fit(X_train, y_train)

    grid_search.fit(X_train, y_train)
    best_model = grid_search.best_estimator_

    # evaluate
    y_pred = best_model.predict(X_test)
    print("Best Model:", best_model)
    print(f"Accuracy Score: {accuracy_score(y_test, y_pred):.2f}")
    print("Confusion Matrix:\n", confusion_matrix(y_test, y_pred))
    print("Classification Report:\n", classification_report(y_test, y_pred))



'''
    DBSCAN Clustering Algorithm
'''

def db_scan_cluster():

    X = df.drop(['TARGET'], axis=1)

    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    db = DBSCAN(eps=0.3, min_samples=12).fit(X_scaled)
    labels = db.labels_

    # number of clusters in labels, ignore noise
    n_clusters = len(set(labels)) - (1 if -1 in labels else 0)
    n_noise = list(labels).count(-1)

    print("Estimated number of clusters: %d" % n_clusters)
    print("Estimated number of noise points: %d" % n_noise)

