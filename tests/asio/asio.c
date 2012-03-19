/* NFSv4.1 client for Windows
 * Copyright © 2012 The Regents of the University of Michigan
 *
 * Olga Kornievskaia <aglo@umich.edu>
 * Casey Bodley <cbodley@umich.edu>
 *
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; either version 2.1 of the License, or (at
 * your option) any later version.
 *
 * This library is distributed in the hope that it will be useful, but
 * without any warranty; without even the implied warranty of merchantability
 * or fitness for a particular purpose.  See the GNU Lesser General Public
 * License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 */

#include <Windows.h>
#include <tchar.h>
#include <stdio.h>
#include <errno.h>


static void PrintErrorMessage(
    IN DWORD dwError)
{
    LPTSTR lpMsgBuf = NULL;
    FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM,
        NULL, dwError, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        (LPTSTR)&lpMsgBuf, 0, NULL);
    _fputts(lpMsgBuf, stderr);
    LocalFree(lpMsgBuf);
}

static SIZE_T parse_buffer_size(LPCTSTR str)
{
    PTCHAR end;
    SIZE_T value = _tcstoul(str, &end, 0);

    if (value == ULONG_MAX && errno == ERANGE)
        return 0;

    if (end) switch (*end) {
    case 0: break;
    case TEXT('g'): case TEXT('G'): value <<= 10;
    case TEXT('m'): case TEXT('M'): value <<= 10;
    case TEXT('k'): case TEXT('K'): value <<= 10; break;
    default: value = 0; break;
    }
    return value;
}

static DWORD resize_file(
    HANDLE file,
    SIZE_T length)
{
    LARGE_INTEGER pointer;
    DWORD pos, status = NO_ERROR;

    // move to the new eof
    pointer.QuadPart = length;
    pos = SetFilePointer(file, pointer.LowPart, &pointer.HighPart, FILE_BEGIN);
    if (pos == INVALID_SET_FILE_POINTER) {
        status = GetLastError();
        if (status) {
            _ftprintf(stderr, TEXT("SetFilePointer() failed to move to ")
                TEXT("position %u with %d: "), length, status);
            goto out;
        }
    }

    // set the new file size
    if (!SetEndOfFile(file)) {
        status = GetLastError();
        _ftprintf(stderr, TEXT("SetEndOfFile() failed with %d: "), status);
    }

    // restore the original file position
    pos = SetFilePointer(file, 0, 0, FILE_BEGIN);
    if (pos == INVALID_SET_FILE_POINTER) {
        status = GetLastError();
        _ftprintf(stderr, TEXT("SetFilePointer() failed to restore ")
            TEXT("the original position with %d: "), status);
        goto out;
    }
out:
    return status;
}

struct async_job {
    OVERLAPPED overlapped;
    LPVOID buffer;
    DWORD started;
    DWORD status;
    DWORD transferred;
};

// make asynchronous calls to WriteFile()
static DWORD jobs_write(
    HANDLE file,
    struct async_job *jobs,
    DWORD chunk,
    DWORD count)
{
    DWORD i, status = NO_ERROR;

    for (i = 0; i < count; i++) {
        // start the job
        jobs[i].started = GetTickCount();
        if (WriteFile(file, jobs[i].buffer, chunk, &jobs[i].transferred, &jobs[i].overlapped)) {
            jobs[i].status = NO_ERROR;
            _tprintf(TEXT("job %u wrote %u bytes synchronously in %u ticks\n"),
                i+1, jobs[i].transferred, GetTickCount() - jobs[i].started);
        } else {
            jobs[i].status = GetLastError();
            if (jobs[i].status != ERROR_IO_PENDING) {
                status = jobs[i].status;
                _ftprintf(stderr, TEXT("WriteFile() failed with %d: "), status);
                break;
            }
        }
        _tprintf(TEXT("started write job %u\n"), i+1);
    }
    return status;
}

// make asynchronous calls to ReadFile()
static DWORD jobs_read(
    HANDLE file,
    struct async_job *jobs,
    DWORD chunk,
    DWORD count)
{
    DWORD i, status = NO_ERROR;

    for (i = 0; i < count; i++) {
        jobs[i].started = GetTickCount();
        if (ReadFile(file, jobs[i].buffer, chunk, &jobs[i].transferred, &jobs[i].overlapped)) {
            jobs[i].status = NO_ERROR;
            _tprintf(TEXT("job %u read %u bytes synchronously in %u ticks\n"),
                i+1, jobs[i].transferred, GetTickCount() - jobs[i].started);
        } else {
            jobs[i].status = GetLastError();
            if (jobs[i].status != ERROR_IO_PENDING) {
                status = jobs[i].status;
                _ftprintf(stderr, TEXT("ReadFile() failed with %d: "), status);
                break;
            }
        }
        _tprintf(TEXT("started read job %u\n"), i+1);
    }
    return status;
}

// use GetOverlappedResult() to wait for all jobs to finish
static DWORD jobs_wait(
    HANDLE file,
    struct async_job *jobs,
    DWORD count)
{
    DWORD i, status = NO_ERROR;

    for (i = 0; i < count; i++) {
        if (jobs[i].status != ERROR_IO_PENDING)
            continue;
        if (!GetOverlappedResult(file, &jobs[i].overlapped, &jobs[i].transferred, TRUE)) {
            status = GetLastError();
            _ftprintf(stderr, TEXT("GetOverlappedResult() failed with %d: "), status);
        }
        _tprintf(TEXT("job %u transferred %u bytes in %u ticks\n"),
            i+1, jobs[i].transferred, GetTickCount() - jobs[i].started);
    }
    return status;
}

static DWORD jobs_run(
    LPCTSTR filename,
    PBYTE buffer,
    SIZE_T length,
    DWORD count)
{
    HANDLE file;
    struct async_job jobs[MAXIMUM_WAIT_OBJECTS] = { 0 };
    const DWORD chunk = (DWORD)(length / count);
    DWORD i, status = NO_ERROR;

    // open or create the file; specify FILE_FLAG_OVERLAPPED for async io
    file = CreateFile(filename, GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED | FILE_FLAG_NO_BUFFERING, NULL);
    if (file == INVALID_HANDLE_VALUE) {
        status = GetLastError();
        _ftprintf(stderr, TEXT("CreateFile('%s') failed with %d: "), filename, status);
        goto out;
    }
    switch (GetLastError()) {
    case ERROR_ALREADY_EXISTS:
        _ftprintf(stderr, TEXT("Opened existing file '%s'.\n"), filename);
        break;
    default:
        _ftprintf(stderr, TEXT("Created file '%s'.\n"), filename);
        break;
    }

    // set the file length first; writes that extend the file must be synchronous
    status = resize_file(file, length);
    if (status)
        goto out_close;

    // create a separate event for each job, or GetOverlappedResult() will mix them up
    for (i = 0; i < count; i++) {
        jobs[i].overlapped.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
        if (jobs[i].overlapped.hEvent == INVALID_HANDLE_VALUE) {
            status = GetLastError();
            _ftprintf(stderr, TEXT("CreateEvent() failed with %d: "), status);
            goto out_events;
        }
        jobs[i].buffer = buffer + i * chunk;
    }

    // start writes and wait for them to finish
    status = jobs_write(file, jobs, chunk, count);
    if (status) goto out_events;
    status = jobs_wait(file, jobs, count);
    if (status) goto out_events;

    // start reads and wait for them to finish
    status = jobs_read(file, jobs, chunk, count);
    if (status) goto out_events;
    status = jobs_wait(file, jobs, count);
    if (status) goto out_events;

out_events:
    // close the event handles
    for (i = 0; i < count; i++)
        CloseHandle(jobs[i].overlapped.hEvent);
out_close:
    CloseHandle(file);
out:
    return status;
}

#define BLOCK_SIZE 512
#define PAGE_SIZE 4096

DWORD __cdecl _tmain(DWORD argc, LPTSTR argv[])
{
    DWORD status = NO_ERROR;
    LPCTSTR filename;
    SIZE_T bytes;
    DWORD count;
    PBYTE buffer;

    // parse the command line
    if (argc < 4) {
        _tprintf(TEXT("Usage: %s <filename> <bytes> <threads>\n"), argv[0]);
        goto out;
    }
    filename = argv[1];

    bytes = parse_buffer_size(argv[2]);
    if (bytes == 0) {
        _tprintf(TEXT("Invalid value for bytes: %s\n"), argv[2]);
        goto out;
    }
    // must be a multiple of the page size for VirtualAlloc()
    if (bytes % PAGE_SIZE) {
        _tprintf(TEXT("bytes %llu must be a multiple of %u\n"), bytes, PAGE_SIZE);
        goto out;
    }

    count = _ttoi(argv[3]);
    if (count <= 0 || count > MAXIMUM_WAIT_OBJECTS) {
        _tprintf(TEXT("Invalid value for threads: %s\n"), argv[3]);
        goto out;
    }
    // chunk size must be a multiple of the block size for FILE_FLAG_NO_BUFFERING
    if ((bytes / count) % BLOCK_SIZE) {
        _tprintf(TEXT("io size (bytes/threads) %llu must be a multiple of %u\n"), bytes / count, BLOCK_SIZE);
        goto out;
    }
    if (bytes/count > ULONG_MAX) {
        _tprintf(TEXT("io size (bytes/threads) %llu must fit in 32 bits for WriteFile()\n"), bytes / count);
        goto out;
    }

    // allocate the buffer; VirtualAlloc guarantees page alignment for FILE_FLAG_NO_BUFFERING
    buffer = VirtualAlloc(NULL, bytes, MEM_COMMIT, PAGE_READWRITE);
    if (buffer == NULL) {
        status = GetLastError();
        _ftprintf(stderr, TEXT("VirtualAlloc(%llu) failed with %d: "), bytes, status);
        goto out;
    }

    status = jobs_run(filename, buffer, bytes, count);

    // free the buffer
    if (!VirtualFree(buffer, 0, MEM_RELEASE)) {
        status = GetLastError();
        _ftprintf(stderr, TEXT("VirtualFree(%p) failed with %d: "), buffer, status);
        goto out;
    }
out:
    if (status) PrintErrorMessage(status);
    return status;
}
