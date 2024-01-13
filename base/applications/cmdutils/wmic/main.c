/*
 * Copyright 2010 Louis Lenders
 * Copyright 2012 Hans Leidekker for CodeWeavers
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

#define COBJMACROS

#include <stdio.h>
#include "windows.h"
#include "ocidl.h"
#include "initguid.h"
#include "objidl.h"
#include "wbemcli.h"
#include "wmic.h"

#include "wine/debug.h"
#include "wine/unicode.h"

WINE_DEFAULT_DEBUG_CHANNEL(wmic);

static const struct
{
    const WCHAR *alias;
    const WCHAR *class;
}
alias_map[] =
{
    { L"bios", L"Win32_BIOS" },
    { L"computersystem", L"Win32_ComputerSystem" },
    { L"cpu", L"Win32_Processor" },
    { L"LogicalDisk", L"Win32_LogicalDisk" },
    { L"nic", L"Win32_NetworkAdapter" },
    { L"os", L"Win32_OperatingSystem" },
    { L"process", L"Win32_Process" }
};

static const WCHAR *find_class( const WCHAR *alias )
{
    unsigned int i;

    for (i = 0; i < ARRAY_SIZE(alias_map); i++)
    {
        if (!strcmpiW( alias, alias_map[i].alias )) return alias_map[i].class;
    }
    return NULL;
}

static inline WCHAR *strdupW( const WCHAR *src )
{
    WCHAR *dst;
    if (!src) return NULL;
    if (!(dst = HeapAlloc( GetProcessHeap(), 0, (strlenW( src ) + 1) * sizeof(WCHAR) ))) return NULL;
    strcpyW( dst, src );
    return dst;
}

static WCHAR *find_prop( IWbemClassObject *class, const WCHAR *prop )
{
    SAFEARRAY *sa;
    WCHAR *ret = NULL;
    LONG i, last_index = 0;
    BSTR str;

    if (IWbemClassObject_GetNames( class, NULL, WBEM_FLAG_ALWAYS, NULL, &sa ) != S_OK) return NULL;

    SafeArrayGetUBound( sa, 1, &last_index );
    for (i = 0; i <= last_index; i++)
    {
        SafeArrayGetElement( sa, &i, &str );
        if (!strcmpiW( str, prop ))
        {
            ret = strdupW( str );
            break;
        }
    }
    SafeArrayDestroy( sa );
    return ret;
}

static int output_string( HANDLE handle, const WCHAR *msg, ... )
{
    va_list va_args;
    int len;
    DWORD count;
    WCHAR buffer[8192];

    va_start( va_args, msg );
    len = vsnprintfW( buffer, ARRAY_SIZE(buffer), msg, va_args );
    va_end( va_args );

    if (!WriteConsoleW( handle, buffer, len, &count, NULL ))
        WriteFile( handle, buffer, len * sizeof(WCHAR), &count, FALSE );

    return count;
}

static int output_error( int msg )
{
    static const WCHAR fmtW[] = {'%','s',0};
    WCHAR buffer[8192];

    LoadStringW( GetModuleHandleW(NULL), msg, buffer, ARRAY_SIZE(buffer));
    return output_string( GetStdHandle(STD_ERROR_HANDLE), fmtW, buffer );
}

static int output_header( const WCHAR *prop, ULONG column_width )
{
    static const WCHAR bomW[] = {0xfeff}, fmtW[] = L"%-*s\t\n";
    int len;
    DWORD count;
    WCHAR buffer[8192];

    len = snprintfW( buffer, ARRAY_SIZE(buffer), fmtW, column_width, prop );

    if (!WriteConsoleW( GetStdHandle(STD_OUTPUT_HANDLE), buffer, len, &count, NULL )) /* redirected */
    {
        WriteFile( GetStdHandle(STD_OUTPUT_HANDLE), bomW, sizeof(bomW), &count, FALSE );
        WriteFile( GetStdHandle(STD_OUTPUT_HANDLE), buffer, len * sizeof(WCHAR), &count, FALSE );
        count += sizeof(bomW);
    }

    return count;
}

static int output_line( const WCHAR *str, ULONG column_width )
{
    static const WCHAR fmtW[] = {'%','-','*','s','\r','\n',0};
    return output_string( GetStdHandle(STD_OUTPUT_HANDLE), fmtW, column_width, str );
}

static int query_prop( const WCHAR *class, const WCHAR *propname )
{
    static const WCHAR select_allW[] = L"SELECT * FROM ";
    static const WCHAR cimv2W[] = L"ROOT\\CIMV2";
    static const WCHAR wqlW[] = {'W','Q','L',0};
    HRESULT hr;
    IWbemLocator *locator = NULL;
    IWbemServices *services = NULL;
    IEnumWbemClassObject *result = NULL;
    LONG flags = WBEM_FLAG_RETURN_IMMEDIATELY | WBEM_FLAG_FORWARD_ONLY;
    BSTR path = NULL, wql = NULL, query = NULL;
    WCHAR *prop = NULL;
    BOOL first = TRUE;
    int len, ret = -1;
    IWbemClassObject *obj;
    ULONG count, width = 0;
    VARIANT v;

    WINE_TRACE("%s, %s\n", debugstr_w(class), debugstr_w(propname));

    CoInitialize( NULL );
    CoInitializeSecurity( NULL, -1, NULL, NULL, RPC_C_AUTHN_LEVEL_DEFAULT,
                          RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE, NULL );

    hr = CoCreateInstance( &CLSID_WbemLocator, NULL, CLSCTX_INPROC_SERVER, &IID_IWbemLocator,
                           (void **)&locator );
    if (hr != S_OK) goto done;

    if (!(path = SysAllocString( cimv2W ))) goto done;
    hr = IWbemLocator_ConnectServer( locator, path, NULL, NULL, NULL, 0, NULL, NULL, &services );
    if (hr != S_OK) goto done;

    len = strlenW( class ) + ARRAY_SIZE(select_allW);
    if (!(query = SysAllocStringLen( NULL, len ))) goto done;
    strcpyW( query, select_allW );
    strcatW( query, class );

    if (!(wql = SysAllocString( wqlW ))) goto done;
    hr = IWbemServices_ExecQuery( services, wql, query, flags, NULL, &result );
    if (hr != S_OK) goto done;

    for (;;) /* get column width */
    {
        IEnumWbemClassObject_Next( result, WBEM_INFINITE, 1, &obj, &count );
        if (!count) break;

        if (!prop && !(prop = find_prop( obj, propname )))
        {
            output_error( STRING_INVALID_QUERY );
            goto done;
        }
        if (IWbemClassObject_Get( obj, prop, 0, &v, NULL, NULL ) == WBEM_S_NO_ERROR)
        {
            VariantChangeType( &v, &v, 0, VT_BSTR );
            width = max( strlenW( V_BSTR( &v ) ), width );
            VariantClear( &v );
        }
        IWbemClassObject_Release( obj );
    }
    width += 2;

    IEnumWbemClassObject_Reset( result );
    for (;;)
    {
        IEnumWbemClassObject_Next( result, WBEM_INFINITE, 1, &obj, &count );
        if (!count) break;

        if (first)
        {
            output_header( prop, width );
            first = FALSE;
        }
        if (IWbemClassObject_Get( obj, prop, 0, &v, NULL, NULL ) == WBEM_S_NO_ERROR)
        {
            VariantChangeType( &v, &v, 0, VT_BSTR );
            output_line( V_BSTR( &v ), width );
            VariantClear( &v );
        }
        IWbemClassObject_Release( obj );
    }
    ret = 0;

done:
    if (result) IEnumWbemClassObject_Release( result );
    if (services) IWbemServices_Release( services );
    if (locator) IWbemLocator_Release( locator );
    SysFreeString( path );
    SysFreeString( query );
    SysFreeString( wql );
    HeapFree( GetProcessHeap(), 0, prop );
    CoUninitialize();
    return ret;
}

int wmain(int argc, WCHAR *argv[])
{
    static const WCHAR getW[] = {'g','e','t',0};
    static const WCHAR quitW[] = {'q','u','i','t',0};
    static const WCHAR exitW[] = {'e','x','i','t',0};
    static const WCHAR pathW[] = {'p','a','t','h',0};
    static const WCHAR classW[] = {'c','l','a','s','s',0};
    static const WCHAR contextW[] = {'c','o','n','t','e','x','t',0};
    const WCHAR *class, *value;
    int i;

    for (i = 1; i < argc && argv[i][0] == '/'; i++)
        WINE_FIXME( "command line switch %s not supported\n", debugstr_w(argv[i]) );

    if (i >= argc)
        goto not_supported;

    if (!strcmpiW( argv[i], quitW ) ||
        !strcmpiW( argv[i], exitW ))
    {
        return 0;
    }

    if (!strcmpiW( argv[i], classW) ||
        !strcmpiW( argv[i], contextW ))
    {
        WINE_FIXME( "command %s not supported\n", debugstr_w(argv[i]) );
        goto not_supported;
    }

    if (!strcmpiW( argv[i], pathW ))
    {
        if (++i >= argc)
        {
            output_error( STRING_INVALID_PATH );
            return 1;
        }
        class = argv[i];
    }
    else
    {
        class = find_class( argv[i] );
        if (!class)
        {
            output_error( STRING_ALIAS_NOT_FOUND );
            return 1;
        }
    }

    if (++i >= argc)
        goto not_supported;

    if (!strcmpiW( argv[i], getW ))
    {
        if (++i >= argc)
            goto not_supported;
        value = argv[i];
        return query_prop( class, value );
    }

not_supported:
    output_error( STRING_CMDLINE_NOT_SUPPORTED );
    return 1;
}
