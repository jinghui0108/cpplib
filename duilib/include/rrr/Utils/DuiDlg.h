#ifndef DUIDLG_H
#define DUIDLG_H

namespace DuiLib
{
class DUILIB_API DuiDlg  :public WindowImplBase
{

public:
  static bool m_IsZip;
  static CDuiString m_ZipFile;
  static CDuiString m_ZipFolder;
  static long m_ZipID;
public:
	DuiDlg(CDuiString className);
	~DuiDlg(void);
	virtual void CreateDlg(HWND wnd,CDuiString xmlName);
	virtual void CreateDlg(CDuiString xmlName);
  
	
	virtual void ShowCenter(bool modal=false);
  virtual void ShowFullScreen();
  virtual void  ShowTaskBar(bool show);
  virtual void FilterEditText(CRichEditUI* ui);
  virtual void NotifyDeal(TNotifyUI& msg)=0;

  template <typename T>
  T  GetCtrlPtr(const char * name){
    return static_cast<T>(m_PaintManager.FindControl(name));
  }
bool m_bFullScreen;
protected:
  virtual LRESULT ResponseDefaultKeyEvent(WPARAM wParam);
public :
  virtual UILIB_RESOURCETYPE GetResourceType() const;
	virtual CDuiString GetSkinFile();
	virtual CDuiString GetSkinFolder();
	virtual LPCTSTR GetResourceID() const;
	virtual CDuiString GetZIPFileName() const;
	virtual LPCTSTR GetWindowClassName() const ;
	virtual UINT GetClassStyle() const ;
	virtual LONG GetStyle() const;

  virtual void OnFinalMessage(HWND hWnd);
	virtual	void	Notify(TNotifyUI& msg); 
	private:
	CDuiString m_className;
	CDuiString m_xmlName;
};

}
#endif

