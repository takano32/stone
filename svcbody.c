
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <process.h>
#include <tchar.h>
#include <string.h>
#include <memory.h>
#include <time.h>

#include "service.h"
#include "svcbody.h"

//
HANDLE 	hInst;
HANDLE 	hWnd;
HANDLE	hKillEvent;
//
BOOL MyReportStatusToSCMgr(DWORD dwCurrentState, DWORD dwWin32ExitCode, DWORD dwWaitHint);
BOOL InitApplication(HANDLE hInstance, DWORD dwArgc, LPTSTR *lpszArgv);

//
//	FUNCTION: ServiceStart
//
//	PURPOSE: Actual code of the service
//			 that does the work.
//
//	PARAMETERS:
//	  dwArgc   - number of command line arguments
//	  lpszArgv - array of command line arguments
//
//	RETURN VALUE:
//	  none
//
VOID ServiceStart(DWORD dwArgc, LPTSTR *lpszArgv)
{
	MSG msg;
	BOOL res;

	// Service initialization
	if (!MyReportStatusToSCMgr(SERVICE_START_PENDING, NO_ERROR, 3000)) return;
	if (!InitApplication(NULL, dwArgc, lpszArgv)) return;
	if (!MyReportStatusToSCMgr(SERVICE_START_PENDING, NO_ERROR, 3000)) return;
	LogEvent(NULL, EVENTLOG_INFORMATION_TYPE, EVID_SVCSTART, NULL, "Service started.");
	if (!MyReportStatusToSCMgr(SERVICE_RUNNING, NO_ERROR, 0)) return;

	// Service is now running, perform work until shutdown
	while ( (res=GetMessage(&msg, NULL, 0, 0)) != 0) {
		TranslateMessage(&msg);    /* Translates virtual key codes			 */
		DispatchMessage(&msg);	   /* Dispatches message to window			 */
	}
	return;
}

//
//	FUNCTION: ServiceStop
//
//	PURPOSE: Stops the service
//
//	PARAMETERS:
//	  none
//
//	RETURN VALUE:
//	  none
//
//	COMMENTS:
//	  If a ServiceStop procedure is going to
//	  take longer than 3 seconds to execute,
//	  it should spawn a thread to execute the
//	  stop code, and return.  Otherwise, the
//	  ServiceControlManager will believe that
//	  the service has stopped responding.
//		
VOID ServiceStop()
{
	LogEvent(NULL, EVENTLOG_INFORMATION_TYPE, EVID_SVCSTOP, NULL, "Service stopping...");
	if (NULL != hKillEvent) {
		SetEvent(hKillEvent);
		Sleep(50);
		CloseHandle(hKillEvent);
	}
	PostMessage(hWnd, WM_QUIT, 0, 0);
}

/****************************************************************************
*
*	 FUNCTION: MyReportStatusToSCMgr(state, exitCode, waitHin)
*
*\***************************************************************************/
BOOL MyReportStatusToSCMgr(DWORD dwCurrentState, DWORD dwWin32ExitCode,	DWORD dwWaitHint)
{
	if (!ReportStatusToSCMgr(dwCurrentState, dwWin32ExitCode, dwWaitHint)) {
		LogEvent(NULL, EVENTLOG_ERROR_TYPE, EVID_SCMERR, NULL, "Problems talking with SCM.");
		return (FALSE);
	}
	return (TRUE);
}

/****************************************************************************
*
*	 FUNCTION: InitApplication(HANDLE)
*
*	 PURPOSE: Initializes data and registers window class
*
*\***************************************************************************/

BOOL InitApplication(HANDLE hInstance, DWORD dwArgc, LPTSTR *lpszArgv)
{
	WNDCLASS  wc;

	wc.style = 0;							/* Class style(s).					  */
	wc.lpfnWndProc = (WNDPROC)MainWndProc;	/* Function to retrieve messages	  */
	wc.cbClsExtra = 0;						/* No per-class extra data. 		  */
	wc.cbWndExtra = 0;						/* No per-window extra data.		  */
	wc.hIcon = NULL;
//	wc.hInstance = hInstance; 				/* Application that owns the class.   */
	wc.hCursor = NULL;
	wc.hbrBackground = NULL;
	wc.lpszMenuName =  NULL;
	wc.lpszClassName = SZWINCLASSNAME;		/* Name used in call to CreateWindow. */

	if (!MyReportStatusToSCMgr(SERVICE_START_PENDING, NO_ERROR, 3000)) return (FALSE);
	RegisterClass(&wc);
	if (!MyReportStatusToSCMgr(SERVICE_START_PENDING, NO_ERROR, 3000)) return (FALSE);

	hWnd = CreateWindow(
		SZWINCLASSNAME,					/* See RegisterClass() call.		  */
		SZSERVICEDISPLAYNAME,			/* Text for window title bar.		  */
		WS_OVERLAPPEDWINDOW,			/* Window style.					  */
		CW_USEDEFAULT,					/* Default horizontal position. 	  */
		CW_USEDEFAULT,					/* Default vertical position.		  */
		CW_USEDEFAULT,					/* width.					  */
		CW_USEDEFAULT,					/* height.					  */
		NULL,							/* Overlapped windows have no parent. */
		NULL,							/* Use the window class menu.		  */
		NULL,							/* This instance owns this window.	  */
		NULL							/* Pointer not needed.				  */
	);

	/* If window could not be created, return "failure" */
	if (!hWnd) {
		LogEvent(NULL, EVENTLOG_INFORMATION_TYPE, EVID_WINERR, NULL, "Could not create window.");
		return (FALSE);
	}
	if (!MyReportStatusToSCMgr(SERVICE_START_PENDING, NO_ERROR, 3000)) return (FALSE);


	// Now start any worker thread
	hKillEvent = CreateEvent(NULL, TRUE, FALSE, SZKILLEVENT);
	if (NULL == hKillEvent) return(FALSE);
	svc_main(hKillEvent);
	return(TRUE);				 /* Returns the value from PostQuitMessage */
}

/****************************************************************************\
*
*	 FUNCTION: MainWndProc(hWnd, unsigned, WORD, LONG)
*
*	 PURPOSE:  Processes main window messages
*
* MESSAGES:
*  WM_CREATE   - Initialize app
*  WM_DESTROY  - destroys window and cleans up things
*
*\***************************************************************************/
LONG APIENTRY MainWndProc(HWND hWnd, UINT message, UINT wParam,	LONG lParam)
{
	int status; 			/* Status Code */
	WORD event;

	switch (message) {
		case WM_CREATE:
			// do init stuff e.g. WSAStartup() here
			break;
		case WM_DESTROY:
			{
				LogEvent(NULL, EVENTLOG_WARNING_TYPE, EVID_KILLED, NULL, "Close request: Stopping.");
				PostQuitMessage(0);
			}
			break;
		default:
			return (DefWindowProc(hWnd, message, wParam, lParam));
	}
	return (0);
}

/*
  For Gnu Emacs.
  Local Variables:
  tab-width: 4
  c-basic-offset: 4
  End:
*/
