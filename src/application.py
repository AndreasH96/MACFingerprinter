from Fingerprint import MACFingerPrinter
import time
import pyshark
import wx


class Application():
    def __init__(self):
        self.Mode = ""
        self.deviceCounter = MACFingerPrinter()
        self.app = wx.App()
        self.WindowSize = wx.Display().GetGeometry() [2:]
        print(self.WindowSize)
        self.frame = wx.Frame(parent = None,title = "Local MAC Address counter",style=wx.MAXIMIZE_BOX |wx.RESIZE_BORDER
	    | wx.SYSTEM_MENU | wx.CAPTION |	 wx.CLOSE_BOX ,size =(self.WindowSize[0],self.WindowSize[1]))
        
        self.frame.SetMinSize(wx.Size(600,400))
        self.frame.Bind(wx.EVT_SIZE, self.sizeChanged,self.frame)
        self.title = wx.StaticText(parent = self.frame, label ="Candidate Thesis Proof of Concept", pos=(0,0),size=(self.WindowSize[0],self.WindowSize[1]/10))
        font = self.title.GetFont()
        font.PointSize += 20
        font = font.Bold()
        self.title.SetFont(font)
        self.title.Fit()


        self.modeSelectTitle = wx.StaticText(parent=self.frame, label ="Select Mode", pos = (100,100),size = (50,50))
        modeSelectTitleFont = self.modeSelectTitle.GetFont()
        modeSelectTitleFont.PointSize += 20
        modeSelectTitleFont = modeSelectTitleFont.Bold()
        self.modeSelectTitle.SetFont(modeSelectTitleFont)

        self.FileModeSelectBox = wx.CheckBox(self.frame, id  = wx.ID_ANY, pos =(100,200), size = (150,50),
        validator = wx.DefaultValidator, label = "Existing pcapng File", style = 1)
        font = self.FileModeSelectBox.GetFont()
        font.PointSize += 10
        self.FileModeSelectBox.SetFont(font)
        self.FileModeSelectBox.Fit()
        self.frame.Bind(wx.EVT_CHECKBOX, self.OnFileModeBoxClick,self.FileModeSelectBox)

        self.LiveModeSelectBox = wx.CheckBox(self.frame, id  = wx.ID_ANY, pos =(100,280), size = (150,50),
        validator = wx.DefaultValidator, label = "Live Capture", style = 1)
        self.LiveModeSelectBox.SetFont(font)
        self.LiveModeSelectBox.Fit()
        self.frame.Bind(wx.EVT_CHECKBOX, self.OnLiveModeBoxClick,self.LiveModeSelectBox)

        

        self.fileSelector = wx.FilePickerCtrl(self.frame, id = wx.ID_ANY, path = "", message = wx.FileSelectorPromptStr, wildcard = wx.FileSelectorDefaultWildcardStr,
        pos = (200,400),size = (80,80), style = wx.FLP_DEFAULT_STYLE | wx.FLP_SMALL,validator =wx.DefaultValidator,name="Select File")
        self.fileSelector.Fit()
        self.fileSelector.Hide()

        self.startButton = wx.Button(parent = self.frame, label = "Start",pos = (100,400),size=(80,80))
        self.startButton.Fit()
        self.frame.Bind(wx.EVT_BUTTON, self.OnStartButtonClick, self.startButton)
        self.ConsoleTitle = wx.StaticText(parent=self.frame, label ="Console", pos = (500,90),size = (40,40))
        font = self.ConsoleTitle.GetFont()
        font.PointSize += 10
        self.ConsoleTitle.SetFont(font)
        self.ConsoleTitle.Fit()
        self.ConsoleWindow = wx.TextCtrl(self.frame,value ="",pos = (500,120),size=(600,500),style = wx.TE_MULTILINE)
        ConsoleWindowFont = self.ConsoleWindow.GetFont()
        ConsoleWindowFont.PointSize -= 2
        self.ConsoleWindow.SetFont(ConsoleWindowFont)
        self.ResultWindow = wx.TextCtrl(self.frame,value ="",pos = (1200,150),size=(350,350),style = wx.TE_READONLY|wx.TE_CENTRE,)
        font = self.ResultWindow.GetFont()
        font.PointSize += 50
        self.ResultWindow.SetFont(font)
        self.ResultWindow.Fit()
        self.resultTitle = wx.StaticText(parent=self.frame, label ="Amount of Devices", pos = (1200,100),size = (20,10))
        font = self.resultTitle.GetFont()
        font.PointSize += 20
        self.resultTitle.SetFont(font)
        self.resultTitle.Fit()


        self.frame.Show()
        self.app.MainLoop()

    def start(self):
        modeSelect =  input("Select Mode, Live or File: ")
        if (modeSelect == "Live") :
            while(1):
                self.deviceCounter.readMACAddresses(mode=modeSelect)
                time.sleep(6)
        elif (modeSelect == "File"):
            self.deviceCounter.readMACAddresses(mode = modeSelect)

    def OnFileModeBoxClick(self,event):
        self.LiveModeSelectBox.SetValue(False)
        if self.FileModeSelectBox.IsChecked():
            self.fileSelector.Show()
        elif not self.FileModeSelectBox.IsChecked():
            self.fileSelector.Hide()
        self.Mode = "File"
        print("File")
    def OnLiveModeBoxClick(self,event):
        self.FileModeSelectBox.SetValue(False)
        self.fileSelector.Hide()
        self.Mode = "Live"
        print("Live")
    def OnStartButtonClick(self,event):
        if  self.Mode == "Live" :
            while(1):
                self.deviceCounter.readMACAddresses(mode=self.Mode,runningApplication= self)
                time.sleep(6)
        elif self.Mode == "File":
            file = self.fileSelector.GetPath()
            #wx.PostEvent(self.updateConsole("Test2"),wx.InitDialogEvent(id=0))
            if  file.endswith(".pcapng"):
                self.deviceCounter = MACFingerPrinter()
                deviceResult = self.deviceCounter.readMACAddresses(mode = self.Mode,selectedFile=file,runningApplication=self)
                self.ResultWindow.SetValue(str(deviceResult[0]))
                self.ResultWindow.Fit()
                for row in deviceResult[1]:
                    self.ConsoleWindow.AppendText("{}\n".format(row))
                
            else:
                print("Please select a file of type .pcapng")
    def updateConsole(self,newLine):
        self.ConsoleWindow.AppendText("\n{}".format(newLine))
    def sizeChanged(self,event):
        width,height = event.GetSize()
        print("Width = ",width," Height = ",height)

application = Application()

