import numpy as np
import matplotlib.pyplot as plt
from matplotlib import style
style.use("ggplot")
from sklearn.datasets.samples_generator import make_blobs
from sklearn.cluster import KMeans

centers = [[1,1], [8,5], [15,10], [3, 10], [20, 3]]

X, _ = make_blobs(n_samples = 150, centers = centers, cluster_std = 1.2)

plt.scatter(X[:,0],X[:,1], color="#1f77b4")
plt.show()

nClusters = 10
variance = []
for i in range(1, nClusters+1):
    print(i)
    kmeans = KMeans(n_clusters=i)
    kmeans.fit(X)
    variance.append(kmeans.score(X) * -1)


centroids = kmeans.cluster_centers_
labels = kmeans.labels_

colors = ["g.","r.","c.","y.", "b."]
"""
for i in range(len(X)):
    plt.plot(X[i][0], X[i][1], colors[labels[i]], markersize = 10)


plt.scatter(centroids[:, 0],centroids[:, 1], marker = "x", s=150, linewidths = 5, zorder = 10)

plt.show()

"""
clstrs = []
for i in range(nClusters):
    clstrs.append(i+1)

plt.plot(np.array(clstrs), np.array(variance), color="#1f77b4")
plt.xlabel("K Clusters")
plt.ylabel("RSS Score")

plt.show()