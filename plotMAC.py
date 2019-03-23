import matplotlib.pyplot as plt


class plotMAC:
    def __init__(self):
        self.Ylabel = None
        self.axis = None
        self.plot = None
        self.XValues= None
        self.YValues = None
        self.color = None
        self.thePlot = plt
    def setYLabel(self,label):
        self.Ylabel = label

    def setXLabel(self,label):
        self.Xlabel = label

    def setPlot(self,xValues,yValues):
        self.XValues = xValues
        self.YValues = yValues
        self.color = 'ro'
    def setAxis(self,newaxis):
        self.axis = newaxis

    def Plot(self):
        self.thePlot.plot(self.XValues,self.YValues,self.color)
        if(self.axis != None):
            self.thePlot.axis(self.axis)
        self.thePlot.show()

"""plotter = plotMAC()
plotter.setPlot([1,2,3,4], [1,4,9,16])
plotter.setAxis([0, 6, 0, 20])
plotter.Plot()"""
