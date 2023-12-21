#pragma comment(lib, "tdh.lib")
#pragma comment(lib, "Dnsapi.lib")
#pragma comment(lib, "ntdll.lib")

// Don't include winsock.h in Windows.h
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <Windows.h>
#include <winsock2.h>
#include <Ws2tcpip.h>
#include <evntrace.h>
#include <evntcons.h>
#include <tdh.h>
#include <stdio.h>
#include <combaseapi.h>
#include <WinDNS.h>
#include <Mstcpip.h>
#include "dns/dns.h"
#include "dns/message.h"

const PCWSTR TRACER_GUID = L"c417102b-e54b-4df6-a1eb-2df432a937e3";
const PCWSTR TRACER_NAME = L"DynDnsMon";
const PCWSTR TRACE_NAME = L"DynDnsMonTraceSession";

const PCWSTR PROVIDER_GUID = L"{EB79061A-A566-4698-9119-3ED2807060E7}"; // Microsoft-Windows-DNS-Server
const ULONGLONG PROVIDER_KEYWORDS = 0x0000000000000100; // DYN_UPDATE_RESPONSE
const USHORT PROVIDER_EVENTID = 264; // DYN_UPDATE_RESPONSE

int verbose = 0;
int gracePeriodSeconds = 0;
HANDLE hTimerQueue = NULL;

#define MAX_IP_STRING_LENGTH sizeof("0000:0000:0000:0000:0000:ffff:192.168.100.100\0")

typedef struct EventTracePropertyData {
	EVENT_TRACE_PROPERTIES Props;
	WCHAR LoggerName[128];
} EventTracePropertyData;

EventTracePropertyData evtTraceProps = { 0 };

typedef struct QueuedDnsRequest {
	CHAR szSourceIP[MAX_IP_STRING_LENGTH];
	WCHAR szZone[254];
	HANDLE hTimerToCleanup;
	ULONG ulMessageSize;
	BYTE message[1];
} QueuedDnsRequest;

static void pCleanup()
{
	ULONG ulRes = ControlTrace(NULL, TRACE_NAME, &evtTraceProps.Props, EVENT_TRACE_CONTROL_STOP);
	if (ulRes == ERROR_SUCCESS)
	{
		if (verbose > 0)
		{
			printf(" [.] Trace session cleaned up.\n");
		}
	}
	else
	{
		printf(" [!] Stopping event trace %ws failed with error %lu\n", TRACE_NAME, ulRes);
	}
}

VOID CALLBACK DelayedCallback(PVOID pOpaque, BOOLEAN bTimerOrWaitFired)
{
	QueuedDnsRequest* pRequest = (QueuedDnsRequest*)pOpaque;

	if (verbose >= 2)
	{
		printf(">>> ");
		for (ULONG i = 0; i < pRequest->ulMessageSize; i++)
		{
			printf("%02X", pRequest->message[i]);
		}
		printf("\n");
	}

	PDNS_RECORD pNameservers = NULL;
	DNS_STATUS status = DnsQuery_W(pRequest->szZone, DNS_TYPE_NS, DNS_QUERY_STANDARD, NULL, &pNameservers, NULL);
	if (status != 0)
	{
		printf(" [!] %s tried to dynamically update zone %ws, but cannot query authoritative servers for that zone (error 0x%lX)\n", pRequest->szSourceIP, pRequest->szZone, status);
		goto cleanup;
	}

	try
	{
		dns::Message msg;
		msg.decode((char*)pRequest->message, pRequest->ulMessageSize);
		if (verbose >= 1)
		{
			printf("   Parsed opcode=%u rcode=%u : %s\n", msg.getOpCode(), msg.getRCode(), msg.asString().c_str());
		}
		if (msg.getOpCode() != 5) // dynamic update
			return;

		auto records = msg.getAuthorities();
		for (auto record : records)
		{
			if (record->getRData() == NULL)
			{
				continue;
			}
			BOOL bUpdateSuccessful = FALSE;
			dns::eRDataType rrType = record->getRData()->getType();
			WCHAR szQueryName[253 + 1] = { 0 };
			MultiByteToWideChar(CP_UTF8, 0, record->getName().c_str(), -1, szQueryName, 254);

			DWORD dwNsTried = 0;
			for (PDNS_RECORD pNameserver = pNameservers; (pNameserver != NULL) && (bUpdateSuccessful == FALSE); pNameserver = pNameserver->pNext)
			{
				DNS_ADDR_ARRAY srvAddr = { 0 };
				DNS_QUERY_REQUEST request = { 0 };
				DNS_QUERY_RESULT results = { 0 };
				CHAR szSrvAddr[46 + 1] = { 0 };

				srvAddr.MaxCount = 1;
				srvAddr.AddrCount = 1;
				results.Version = DNS_QUERY_RESULTS_VERSION1;
				request.Version = DNS_QUERY_REQUEST_VERSION1;
				request.QueryName = szQueryName;
				request.QueryType = rrType;
				request.pDnsServerList = &srvAddr;

				if (pNameserver->wType == DNS_TYPE_A)
				{
					PSOCKADDR_IN pSrvSockAddr = (PSOCKADDR_IN)&(srvAddr.AddrArray[0].MaxSa);
					srvAddr.Family = AF_INET;
					pSrvSockAddr->sin_family = AF_INET;
					pSrvSockAddr->sin_addr.S_un.S_addr = pNameserver->Data.A.IpAddress;
					RtlIpv4AddressToStringA((const in_addr*)&(pNameserver->Data.A.IpAddress), szSrvAddr);
				}
				else if (pNameserver->wType == DNS_TYPE_AAAA)
				{
					SOCKADDR_IN6 *pSrvSockAddr = (SOCKADDR_IN6*)&(srvAddr.AddrArray[0].MaxSa);
					srvAddr.Family = AF_INET6;
					pSrvSockAddr->sin6_family = AF_INET6;
					memcpy(&(pSrvSockAddr->sin6_addr.u.Byte), &(pNameserver->Data.AAAA.Ip6Address), sizeof(pNameserver->Data.AAAA.Ip6Address));
					RtlIpv6AddressToStringA((const in6_addr*)&(pNameserver->Data.AAAA.Ip6Address), szSrvAddr);
				}
				else
				{
					continue;
				}

				dwNsTried++;
				status = DnsQueryEx(&request, &results, NULL);
				if (status == DNS_ERROR_RCODE_NAME_ERROR)
				{
					if (verbose >= 2)
					{
						printf(" [.] Record does not exist on %s\n", szSrvAddr);
					}
					continue;
				}
				if (status != 0)
				{
					printf(" [!] %s tried to dynamically update zone %ws (%ws -> %s) and I cannot query server %s in that zone (error 0x%lX)\n", pRequest->szSourceIP, pRequest->szZone, szQueryName, record->asString().c_str(), szSrvAddr, status);
					continue;
				}

				for (PDNS_RECORD pExisting = results.pQueryRecords; pExisting != NULL; pExisting = pExisting->pNext)
				{
					if (pExisting->wType != rrType)
						continue;
					if (rrType == dns::eRDataType::RDATA_A)
					{
						dns::RDataA* rr = (dns::RDataA*)record->getRData();
						dns::uchar* addr = rr->getAddress();
						if (memcmp(&(pExisting->Data.A), addr, sizeof(pExisting->Data.A)) == 0)
						{
							bUpdateSuccessful = TRUE;
							break;
						}
					}
					else if (rrType == dns::eRDataType::RDATA_AAAA)
					{
						dns::RDataAAAA* rr = (dns::RDataAAAA*)record->getRData();
						dns::uchar* addr = rr->getAddress();
						if (memcmp(&(pExisting->Data.AAAA), addr, sizeof(pExisting->Data.AAAA)) == 0)
						{
							bUpdateSuccessful = TRUE;
							break;
						}
					}
					else
					{
						printf(" [!] %s used unsupported record type %u\n", pRequest->szSourceIP, rrType);
					}
				}
				DnsRecordListFree(results.pQueryRecords, DnsFreeRecordList);

				if ((verbose >= 2) && (bUpdateSuccessful == TRUE))
				{
					printf(" [.] Record already up to date on %s, nothing to do\n", szSrvAddr);
				}
			}

			if (dwNsTried == 0)
			{
				printf(" [!] %s tried to dynamically update zone %ws (%ws -> %s) but cannot find a nameserver for that zone\n", pRequest->szSourceIP, pRequest->szZone, szQueryName, record->asString().c_str());
			}
			else if (bUpdateSuccessful == FALSE)
			{
				printf(" [!] %s failed to dynamically update zone %ws (%ws -> %s)\n", pRequest->szSourceIP, pRequest->szZone, szQueryName, record->asString().c_str());
			}
		}
	}
	catch (const std::exception& exc)
	{
		printf(" [!] Exception when parsing request: %s\n", exc.what());
	}

	DnsRecordListFree(pNameservers, DnsFreeRecordList);

cleanup:
	if (!DeleteTimerQueueTimer(hTimerQueue, pRequest->hTimerToCleanup, NULL))
	{
		DWORD dwErr = GetLastError();
		if (dwErr != ERROR_IO_PENDING)
		{
			printf(" [!] Failed to release timer queue handle (error %lu)\n", GetLastError());
		}
	}
}

static void pEventRecordCallback(PEVENT_RECORD pEvent)
{
	ULONG ulBufferSize = 0;
	UINT32 rcode = 0;
	TDHSTATUS status;
	PROPERTY_DATA_DESCRIPTOR propDescriptor = { 0 };
	propDescriptor.ArrayIndex = ULONG_MAX;

	propDescriptor.PropertyName = (ULONGLONG)L"RCODE";
	status = TdhGetProperty(pEvent, 0, NULL, 1, &propDescriptor, sizeof(rcode), (PBYTE)&rcode);
	if (status != ERROR_SUCCESS)
	{
		printf(" [!] Cannot fetch rcode from event, error 0x%lX\n", status);
		pCleanup();
		exit(8);
	}
	if (rcode != 5) // ERROR_ACCESS_DENIED
	{
		return; // ignore non-failed requests
	}

	propDescriptor.PropertyName = (ULONGLONG)L"PacketData";
	status = TdhGetPropertySize(pEvent, 0, NULL, 1, &propDescriptor, &ulBufferSize);
	if (status != ERROR_SUCCESS)
	{
		printf(" [!] Cannot fetch packet data size from event, error 0x%lX\n", status);
		pCleanup();
		exit(9);
	}

	QueuedDnsRequest *pQueued = (QueuedDnsRequest*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(QueuedDnsRequest) + ulBufferSize);
	if (pQueued == NULL)
	{
		printf(" [!] Cannot allocate memory for packet data (%lu bytes)\n", ulBufferSize);
		pCleanup();
		exit(10);
	}
	pQueued->ulMessageSize = ulBufferSize;

	status = TdhGetProperty(pEvent, 0, NULL, 1, &propDescriptor, ulBufferSize, pQueued->message);
	if (status != ERROR_SUCCESS)
	{
		printf(" [!] Cannot fetch packet data from event, error 0x%lX\n", status);
		pCleanup();
		exit(12);
	}

	propDescriptor.PropertyName = (ULONGLONG)L"Destination";
	status = TdhGetProperty(pEvent, 0, NULL, 1, &propDescriptor, sizeof(pQueued->szSourceIP), (PBYTE)pQueued->szSourceIP);
	if (status != ERROR_SUCCESS)
	{
		printf(" [!] Cannot fetch source IP from event, error 0x%lX\n", status);
		pCleanup();
		exit(11);
	}

	propDescriptor.PropertyName = (ULONGLONG)L"Zone";
	status = TdhGetProperty(pEvent, 0, NULL, 1, &propDescriptor, sizeof(pQueued->szZone), (PBYTE)pQueued->szZone);
	if (status != ERROR_SUCCESS)
	{
		printf(" [!] Cannot fetch zone name from event, error 0x%lX\n", status);
		pCleanup();
		exit(11);
	}

	if (!CreateTimerQueueTimer(&(pQueued->hTimerToCleanup), hTimerQueue,
		(WAITORTIMERCALLBACK)DelayedCallback, (PVOID)pQueued, gracePeriodSeconds * 1000, 0, WT_EXECUTEONLYONCE))
	{
		printf(" [!] Cannot queue a delayed DNS check, error %lu\n", GetLastError());
		pCleanup();
		exit(13);
	}
}

static BOOL WINAPI pConsoleSignalHandler(DWORD dwSignal)
{
	if (dwSignal == CTRL_C_EVENT)
	{
		pCleanup();
	}
	return TRUE;
}

int main(int argc, const char *argv[])
{
	if (argc >= 2)
	{
		gracePeriodSeconds = atoi(argv[1]);
	}
	if (argc < 2 || gracePeriodSeconds < 1)
	{
		printf("Usage: %s <grace period> [-v|-vv]\n", argv[0]);
		printf("\n");
		printf("Specify a grace period in seconds corresponding to the longest\n");
		printf("possible delay before a successful dynamic DNS update applied\n");
		printf("on another DNS server can be seen by this server\n");
		printf("\n");
		printf("Use -v for increased verbosity\n");
		printf("Use -vv for debugging (very verbose)\n");
		return 1;
	}
	if (argc > 2 && _stricmp("-v", argv[2]) == 0)
		verbose = 1;
	if (argc > 2 && _stricmp("-vv", argv[2]) == 0)
		verbose = 2;
	
	if (verbose > 0)
		printf(" [.] Started\n");

	hTimerQueue = CreateTimerQueue();
	if (NULL == hTimerQueue)
	{
		printf(" [!] Creating timer queue returned error %lu\n", GetLastError());
		return 1;
	}

	evtTraceProps.Props.Wnode.BufferSize = sizeof(evtTraceProps);
	evtTraceProps.Props.Wnode.Flags = WNODE_FLAG_TRACED_GUID;
	CLSIDFromString(TRACER_GUID, &evtTraceProps.Props.Wnode.Guid);
	evtTraceProps.Props.LoggerNameOffset = offsetof(EventTracePropertyData, LoggerName);
	evtTraceProps.Props.BufferSize = 16;
	evtTraceProps.Props.MinimumBuffers = 0;
	evtTraceProps.Props.MaximumBuffers = 0; // TODO: check this really disables any limit
	evtTraceProps.Props.LogFileMode = EVENT_TRACE_REAL_TIME_MODE; // don't create a file on disk, optimize by directly delivering us events
	evtTraceProps.Props.LogFileNameOffset = 0; // no log file, so no log file name
	evtTraceProps.Props.FlushTimer = 1; // deliver buffered events every 1s, don't risk losing events due to a burst
	wcscpy_s(evtTraceProps.LoggerName, TRACER_NAME);

	// Cleanup any leftover session
	ULONG ulRes = ControlTrace(NULL, TRACE_NAME, &evtTraceProps.Props, EVENT_TRACE_CONTROL_STOP);
	if ((ulRes != ERROR_SUCCESS) && (ulRes != ERROR_WMI_INSTANCE_NOT_FOUND))
	{
		printf(" [!] Stopping leftover event trace %ws returned error %lu\n", TRACE_NAME, ulRes);
		return 1;
	}

	TRACEHANDLE hTrace = NULL;
	ulRes = StartTrace(&hTrace, TRACE_NAME, &evtTraceProps.Props);
	if (ulRes != ERROR_SUCCESS)
	{
		printf(" [!] Could not create event trace %ws : error %lu\n", TRACE_NAME, ulRes);
		return 2;
	}
	if (verbose > 0)
	{
		printf(" [+] Trace session created\n");
	}

	if (!SetConsoleCtrlHandler(pConsoleSignalHandler, TRUE))
	{
		printf(" [!] Could not set Ctrl-C handler, will not be able to exit cleanly\n");
	}

	EVENT_TRACE_LOGFILE evtTraceFile = { 0 };
	evtTraceFile.LoggerName = (PWSTR)TRACE_NAME;
	evtTraceFile.EventRecordCallback = pEventRecordCallback;
	evtTraceFile.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
	TRACEHANDLE hRealtimeTrace = OpenTrace(&evtTraceFile);
	if (hRealtimeTrace == INVALID_PROCESSTRACE_HANDLE)
	{
		printf(" [!] Could not acquire realtime trace handle : error %lu\n", GetLastError());
		return 2;
	}
	if (verbose > 0)
	{
		printf(" [+] Real time event consumer subscribed\n");
	}

	GUID guidProvider;
	ENABLE_TRACE_PARAMETERS providerParams = { 0 };
	providerParams.Version = ENABLE_TRACE_PARAMETERS_VERSION_2;
	CLSIDFromString(PROVIDER_GUID, &guidProvider);
	ulRes = EnableTraceEx2(hTrace, &guidProvider, EVENT_CONTROL_CODE_ENABLE_PROVIDER, TRACE_LEVEL_INFORMATION, PROVIDER_KEYWORDS, 0, INFINITE, &providerParams);
	if (ulRes != ERROR_SUCCESS)
	{
		printf(" [!] Could not add provider to trace session %ws : error %lu\n", TRACE_NAME, ulRes);
		return 3;
	}
	printf(" [+] Provider enabled, listening for events ...\n");
	ProcessTrace(&hRealtimeTrace, 1, NULL, NULL);
	
	CloseTrace(hRealtimeTrace);
	return 0;
}