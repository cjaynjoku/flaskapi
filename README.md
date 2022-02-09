#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <boost/log/core.hpp>
#include <boost/log/trivial.hpp>
#include <boost/log/expressions.hpp>
#include <boost/log/sinks/text_file_backend.hpp>
#include <boost/log/utility/setup/file.hpp>
#include <boost/log/utility/setup/common_attributes.hpp>
#include <boost/log/sources/severity_logger.hpp>
#include <boost/log/sources/record_ostream.hpp>
#include <boost/algorithm/string.hpp>
#include "boost/date_time/posix_time/posix_time_types.hpp"
#include <boost/asio.hpp>
#include <ctime>
#include <windows.h>
#include <cstdlib>


namespace logging = boost::log;
namespace src = boost::log::sources;
namespace sinks = boost::log::sinks;
namespace keywords = boost::log::keywords;
typedef sinks::synchronous_sink< sinks::text_file_backend > sink_t;
boost::shared_ptr< sink_t > g_file_sink;


#ifdef _win32

#include <windows.h>
#include <stdio.h>
#include <conio.h>
#include <leechcore.h>
#include <vmmdll.h>
#pragma comment(lib, "leechcore")
#pragma comment(lib, "vmm")

#endif /* _win32 */
#ifdef linux

#include <leechcore.h>
#include <vmmdll.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define true                                1
#define false                               0
#define lmem_zeroinit                       0x0040
#define _getch()                            (getchar())
#define zeromemory(pb, cb)                  (memset(pb, 0, cb))
#define sleep(dwmilliseconds)               (usleep(1000*dwmilliseconds))
#define min(a, b)                           (((a) < (b)) ? (a) : (b))
#define image_scn_mem_execute               0x20000000
#define image_scn_mem_read                  0x40000000
#define image_scn_mem_write                 0x80000000

handle localalloc(dword uflags, size_t ubytes)
{
    handle h = malloc(ubytes);
    if(h && (uflags & lmem_zeroinit)) {
        memset(h, 0, ubytes);
    }
    return h;
}

void localfree(handle hmem)
{
    free(hmem);
}

#endif /* linux */

#define _initialize_from_file    "z:\\x64\\win10-x64-1909-18363-1.core"

void showkeypress()
{
    printf("press any key to continue ...\n");
    sleep(250);
    _getch();
}

void printhexascii(_in_ pbyte pb, _in_ dword cb)
{
    lpstr sz;
    dword szmax = 0;
    vmmdll_utilfillhexascii(pb, cb, 0, null, &szmax);
    if(!(sz = localalloc(0, szmax))) { return; }
    vmmdll_utilfillhexascii(pb, cb, 0, sz, &szmax);
    printf("%s", sz);
    localfree(sz);
}

void callbacklist_addfile(_inout_ handle h, _in_ lpstr uszname, _in_ ulong64 cb, _in_opt_ pvmmdll_vfs_filelist_exinfo pexinfo)
{
    if(uszname) {
        printf("         file: '%s'\tsize: %lli\n", uszname, cb);
    }
}

void callbacklist_adddirectory(_inout_ handle h, _in_ lpstr uszname, _in_opt_ pvmmdll_vfs_filelist_exinfo pexinfo)
{
    if(uszname) {
        printf("         dir:  '%s'\n", uszname);
    }
}

void vadmap_protection(_in_ pvmmdll_map_vadentry pvad, _out_writes_(6) lpstr sz)
{
    byte vh = (byte)pvad->protection >> 3;
    byte vl = (byte)pvad->protection & 7;
    sz[0] = pvad->fprivatememory ? 'p' : '-';                                    // private memory
    sz[1] = (vh & 2) ? ((vh & 1) ? 'm' : 'g') : ((vh & 1) ? 'n' : '-');         // -/no_cache/guard/writecombine
    sz[2] = ((vl == 1) || (vl == 3) || (vl == 4) || (vl == 6)) ? 'r' : '-';     // copy on write
    sz[3] = (vl & 4) ? 'w' : '-';                                               // write
    sz[4] = (vl & 2) ? 'x' : '-';                                               // execute
    sz[5] = ((vl == 5) || (vl == 7)) ? 'c' : '-';                               // copy on write
    if(sz[1] != '-' && sz[2] == '-' && sz[3] == '-' && sz[4] == '-' && sz[5] == '-') { sz[1] = '-'; }
}

lpstr vadmap_type(_in_ pvmmdll_map_vadentry pvad)
{
    if(pvad->fimage) {
        return "image";
    } else if(pvad->ffile) {
        return "file ";
    } else if(pvad->fheap) {
        return "heap ";
    } else if(pvad->fstack) {
        return "stack";
    } else if(pvad->fteb) {
        return "teb  ";
    } else if(pvad->fpagefile) {
        return "pf   ";
    } else {
        return "     ";
    }
}

int setting()
{
    bool result;
    ntstatus nt;
    dword i, dwpid;
    dword dw = 0;
    qword va;
    byte pbpage1[0x1000], pbpage2[0x1000];

#ifdef _initialize_from_file
    // initialize pcileech dll with a memory dump file.
    printf("------------------------------------------------------------\n");
    printf("# initialize from file:                                     \n");
    showkeypress();
    printf("call:    vmmdll_initializefile\n");
    result = vmmdll_initialize(3, (lpstr[]) { "", "-device", _initialize_from_file });
    if(result) {
        printf("success: vmmdll_initializefile\n");
    } else {
        printf("fail:    vmmdll_initializefile\n");
        return 1;
    }
#endif /* _initialize_from_file */

#ifdef _initialize_from_fpga
    // initialize vmm dll from a linked pcileech with a fpga hardware device
    printf("------------------------------------------------------------\n");
    printf("# initialize from fpga:                                     \n");
    showkeypress();
    printf("call:    vmmdll_initialize\n");
    result = vmmdll_initialize(3, (lpstr[]) { "", "-device", "fpga" });
    if(result) {
        printf("success: vmmdll_initialize\n");
    } else {
        printf("fail:    vmmdll_initialize\n");
        return 1;
    }
    // retrieve the id of the fppa (sp605/pciescreamer/ac701 ...) and the bitstream version
    ulong64 qwid, qwversionmajor, qwversionminor;
    showkeypress();
    printf("call:    vmmdll_configget\n");
    result =
        vmmdll_configget(lc_opt_fpga_fpga_id, &qwid) &&
        vmmdll_configget(lc_opt_fpga_version_major, &qwversionmajor) &&
        vmmdll_configget(lc_opt_fpga_version_minor, &qwversionminor);
    if(result) {
        printf("success: vmmdll_configget\n");
        printf("         id = %lli\n", qwid);
        printf("         version = %lli.%lli\n", qwversionmajor, qwversionminor);
    } else {
        printf("fail:    vmmdll_configget\n");
        return 1;
    }
    // set pcie config space status register flags auto-clear [master abort].
    // this requires bitstream version 4.7 or above. by default the flags are
    // reset evry ms. if timing are to be changed it's possible to write a new
    // timing value to pcileech pcie register at address: 0x054 (dword-value,
    // tickcount of multiples of 62.5mhz ticks).
    if((qwversionmajor >= 4) && ((qwversionmajor >= 5) || (qwversionminor >= 7)))
    {
        handle hlc;
        lc_config lcconfig = {
            .dwversion = lc_config_version,
            .szdevice = "existing"
        };
        // fetch already existing leechcore handle.
        hlc = lccreate(&lcconfig);
        if(hlc) {
            // enable auto-clear of status register [master abort].
            lccommand(hlc, lc_cmd_fpga_cfgregpcie_markwr | 0x002, 4, (byte[4]) { 0x10, 0x00, 0x10, 0x00 }, null, null);
            printf("success: lccommand: status register auto-clear\n");
            // close leechcore handle.
            lcclose(hlc);
        }
    }
#endif /* _initialize_from_fpga */
    
    // retrieve pid of explorer.exe
    // nb! if multiple explorer.exe exists only one will be returned by this
    // specific function call. please see .h file for additional information
    // about how to retrieve the complete list of pids in the system by using
    // the function pcileech_vmmprocesslistpids instead.
    printf("------------------------------------------------------------\n");
    printf("# get pid from the first 'explorer.exe' process found.      \n");
    showkeypress();
    printf("call:    vmmdll_pidgetfromname\n");
    result = vmmdll_pidgetfromname("explorer.exe", &dwpid);
    if(result) {
        printf("success: vmmdll_pidgetfromname\n");
        printf("         pid = %i\n", dwpid);
    } else {
        printf("fail:    vmmdll_pidgetfromname\n");
        return 1;
    }
    

    // read physical memory at physical address 0x1000 and display the first
    // 0x100 bytes on-screen.
    printf("------------------------------------------------------------\n");
    printf("# read from physical memory (0x1000 bytes @ 0x1000).        \n");
    showkeypress();
    printf("call:    vmmdll_memread\n");
    result = vmmdll_memread(-1, 0x1000, pbpage1, 0x1000);
    if(result) {
        printf("success: vmmdll_memread\n");
        printhexascii(pbpage1, 0x100);
    } else {
        printf("fail:    vmmdll_memread\n");
        return 1;
    }

    
    // write physical memory at physical address 0x1000 and display the first
    // 0x100 bytes on-screen - afterwards. maybe result of write is in there?
    // (only if device is capable of writes and target system accepts writes)
    printf("------------------------------------------------------------\n");
    printf("# try write to physical memory at address 0x1000.           \n");
    printf("     nb! write capable device is required for success!      \n");
    printf("     (1) read existing data from physical memory.           \n");
    printf("     (2) try write to physical memory at 0x1000.            \n");
    printf("         bytes written:  11112222333344445555666677778888   \n");
    printf("     (3) read resulting data from physical memory.          \n");
    showkeypress();
    printf("call:    vmmdll_memread - before write\n");
    result = vmmdll_memread(-1, 0x1000, pbpage1, 0x1000);
    if(result) {
        printf("success: vmmdll_memread - before write\n");
        printhexascii(pbpage1, 0x100);
    } else {
        printf("fail:    vmmdll_memread - before write\n");
        return 1;
    }
    printf("call:    vmmdll_memwrite\n");
    dword cbwritedataphysical = 0x20;
    byte pbwritedataphysical[0x20] = {
        0x11, 0x11, 0x11, 0x11, 0x22, 0x22, 0x22, 0x22,
        0x33, 0x33, 0x33, 0x33, 0x44, 0x44, 0x44, 0x44,
        0x55, 0x55, 0x55, 0x55, 0x66, 0x66, 0x66, 0x66,
        0x77, 0x77, 0x77, 0x77, 0x88, 0x88, 0x88, 0x88,
    };
    vmmdll_memwrite(-1, 0x1000, pbwritedataphysical, cbwritedataphysical);
    printf("call:    vmmdll_memread - after write\n");
    result = vmmdll_memread(-1, 0x1000, pbpage1, 0x1000);
    if(result) {
        printf("success: vmmdll_memread - after write\n");
        printhexascii(pbpage1, 0x100);
    } else {
        printf("fail:    vmmdll_memread - after write\n");
        return 1;
    }


    // retrieve pid of explorer.exe
    // nb! if multiple explorer.exe exists only one will be returned by this
    // specific function call. please see .h file for additional information
    // about how to retrieve the complete list of pids in the system by using
    // the function pcileech_vmmprocesslistpids instead.
    printf("------------------------------------------------------------\n");
    printf("# get pid from the first 'explorer.exe' process found.      \n");
    showkeypress();
    printf("call:    vmmdll_pidgetfromname\n");
    result = vmmdll_pidgetfromname("explorer.exe", &dwpid);
    if(result) {
        printf("success: vmmdll_pidgetfromname\n");
        printf("         pid = %i\n", dwpid);
    } else {
        printf("fail:    vmmdll_pidgetfromname\n");
        return 1;
    }


    // retrieve additional process information such as: name of the process,
    // pml4 (pagedirectorybase) pml4-user (if exists) and process state.
    printf("------------------------------------------------------------\n");
    printf("# get process information from 'explorer.exe'.              \n");
    showkeypress();
    vmmdll_process_information processinformation;
    size_t cbprocessinformation = sizeof(vmmdll_process_information);
    zeromemory(&processinformation, sizeof(vmmdll_process_information));
    processinformation.magic = vmmdll_process_information_magic;
    processinformation.wversion = vmmdll_process_information_version;
    printf("call:    vmmdll_processgetinformation\n");
    result = vmmdll_processgetinformation(dwpid, &processinformation, &cbprocessinformation);
    if(result) {
        printf("success: vmmdll_processgetinformation\n");
        printf("         name = %s\n", processinformation.szname);
        printf("         pagedirectorybase = 0x%016llx\n", processinformation.padtb);
        printf("         pagedirectorybaseuser = 0x%016llx\n", processinformation.padtb_useropt);
        printf("         processstate = 0x%08x\n", processinformation.dwstate);
        printf("         pid = 0x%08x\n", processinformation.dwpid);
        printf("         parentpid = 0x%08x\n", processinformation.dwppid);
    } else {
        printf("fail:    vmmdll_processgetinformation\n");
        return 1;
    }

    
    // retrieve the memory map from the page table. this function also tries to
    // make additional parsing to identify modules and tag the memory map with
    // them. this is done by multiple methods internally and may sometimes be
    // more resilient against anti-reversing techniques that may be employed in
    // some processes.
    //
    // note! vmmdll_map_getpte() comes in two variants. the wide-char version
    //       vmmdll_map_getptew() is only available on windows whilst the utf-8
    //       vmmdll_map_getpteu() version is available on linux and windows.
    printf("------------------------------------------------------------\n");
    printf("# get pte memory map of 'explorer.exe'.                     \n");
    showkeypress();
    dword cbptemap = 0;
    pvmmdll_map_pte pptemap = null;
    pvmmdll_map_pteentry pptemapentry;
    printf("call:    vmmdll_map_getpteu #1\n");
    result = vmmdll_map_getpteu(dwpid, null, &cbptemap, true);
    if(result) {
        printf("success: vmmdll_map_getpteu #1\n");
        printf("         bytecount = %i\n", cbptemap);
    } else {
        printf("fail:    vmmdll_map_getpteu #1\n");
        return 1;
    }
    pptemap = (pvmmdll_map_pte)localalloc(0, cbptemap);
    if(!pptemap) {
        printf("fail:    outofmemory\n");
        return 1;
    }
    printf("call:    vmmdll_map_getpteu #2\n");
    result = vmmdll_map_getpteu(dwpid, pptemap, &cbptemap, true);
    if(!result) {
        printf("fail:    vmmdll_map_getpteu #2\n");
        return 1;
    }
    if(pptemap->dwversion != vmmdll_map_pte_version) {
        printf("fail:    vmmdll_map_getpteu - bad version\n");
        return 1;
    }
    {
        printf("success: vmmdll_map_getpteu #2\n");
        printf("         #      #pages adress_range                      srwx\n");
        printf("         ====================================================\n");
        for(i = 0; i < pptemap->cmap; i++) {
            pptemapentry = &pptemap->pmap[i];
            printf(
                "         %04x %8x %016llx-%016llx %sr%s%s%s%s\n",
                i,
                (dword)pptemapentry->cpages,
                pptemapentry->vabase,
                pptemapentry->vabase + (pptemapentry->cpages << 12) - 1,
                pptemapentry->fpage & vmmdll_memmap_flag_page_ns ? "-" : "s",
                pptemapentry->fpage & vmmdll_memmap_flag_page_w ? "w" : "-",
                pptemapentry->fpage & vmmdll_memmap_flag_page_nx ? "-" : "x",
                pptemapentry->fwow64 ? " 32 " : "    ",
                pptemapentry->usztext
            );
        }
        localfree(pptemap);
        pptemap = null;
    }


    // retrieve the memory map from the virtual address descriptors (vad). this
    // function also makes additional parsing to identify modules and tag the
    // memory map with them.
    printf("------------------------------------------------------------\n");
    printf("# get vad memory map of 'explorer.exe'.                     \n");
    showkeypress();
    char szvadprotection[7] = { 0 };
    dword cbvadmap = 0;
    pvmmdll_map_vad pvadmap = null;
    pvmmdll_map_vadentry pvadmapentry;
    printf("call:    vmmdll_map_getvadu #1\n");
    result = vmmdll_map_getvadu(dwpid, null, &cbvadmap, true);
    if(result) {
        printf("success: vmmdll_map_getvadu #1\n");
        printf("         bytecount = %i\n", cbvadmap);
    } else {
        printf("fail:    vmmdll_map_getvadu #1\n");
        return 1;
    }
    pvadmap = (pvmmdll_map_vad)localalloc(0, cbvadmap);
    if(!pvadmap) {
        printf("fail:    outofmemory\n");
        return 1;
    }
    printf("call:    vmmdll_map_getvadu #2\n");
    result = vmmdll_map_getvadu(dwpid, pvadmap, &cbvadmap, true);
    if(!result) {
        printf("fail:    vmmdll_map_getvadu #2\n");
        return 1;
    }
    if(pvadmap->dwversion != vmmdll_map_vad_version) {
        printf("fail:    vmmdll_map_getvadu - bad version\n");
        return 1;
    }
    {
        printf("success: vmmdll_map_getvadu #2\n");
        printf("         #    adress_range                      kernel_addr        type  prot   info \n");
        printf("         ============================================================================\n");
        for(i = 0; i < pvadmap->cmap; i++) {
            pvadmapentry = &pvadmap->pmap[i];
            vadmap_protection(pvadmapentry, szvadprotection);
            printf(
                "         %04x %016llx-%016llx [%016llx] %s %s %s\n",
                i,
                pvadmapentry->vastart,
                pvadmapentry->vaend,
                pvadmapentry->vavad,
                vadmap_type(pvadmapentry),
                szvadprotection,
                pvadmapentry->usztext
            );
        }
        localfree(pvadmap);
        pvadmap = null;
    }


    // retrieve the list of loaded dlls from the process. please note that this
    // list is retrieved by parsing in-process memory structures such as the
    // process environment block (peb) which may be partly destroyed in some
    // processes due to obfuscation and anti-reversing. if that is the case the
    // memory map may use alternative parsing techniques to list dlls.
    printf("------------------------------------------------------------\n");
    printf("# get module map of 'explorer.exe'.                         \n");
    showkeypress();
    dword cbmodulemap = 0;
    pvmmdll_map_module pmodulemap = null;
    printf("call:    vmmdll_map_getmoduleu #1\n");
    result = vmmdll_map_getmoduleu(dwpid, null, &cbmodulemap);
    if(result) {
        printf("success: vmmdll_map_getmoduleu #1\n");
        printf("         bytecount = %i\n", cbmodulemap);
    } else {
        printf("fail:    vmmdll_map_getmoduleu #1\n");
        return 1;
    }
    pmodulemap = (pvmmdll_map_module)localalloc(0, cbmodulemap);
    if(!pmodulemap) {
        printf("fail:    outofmemory\n");
        return 1;
    }
    printf("call:    vmmdll_map_getmoduleu #2\n");
    result = vmmdll_map_getmoduleu(dwpid, pmodulemap, &cbmodulemap);
    if(!result) {
        printf("fail:    vmmdll_map_getmoduleu #2\n");
        return 1;
    }
    if(pmodulemap->dwversion != vmmdll_map_module_version) {
        printf("fail:    vmmdll_map_getmoduleu - bad version\n");
        return 1;
    }
    {
        printf("success: vmmdll_map_getmoduleu #2\n");
        printf("         module_name                                 base             size     entry           path\n");
        printf("         ==========================================================================================\n");
        for(i = 0; i < pmodulemap->cmap; i++) {
            printf(
                "         %-40.40s %s %016llx %08x %016llx %s\n",
                pmodulemap->pmap[i].usztext,
                pmodulemap->pmap[i].fwow64 ? "32" : "  ",
                pmodulemap->pmap[i].vabase,
                pmodulemap->pmap[i].cbimagesize,
                pmodulemap->pmap[i].vaentry,
                pmodulemap->pmap[i].uszfullname
            );
        }
        localfree(pmodulemap);
        pmodulemap = null;
    }


    // retrieve the list of unloaded dlls from the process. please note that
    // windows only keeps references of the most recent 50-64 entries.
    printf("------------------------------------------------------------\n");
    printf("# get unloaded module map of 'explorer.exe'.                \n");
    showkeypress();
    dword cbunloadedmap = 0;
    pvmmdll_map_unloadedmodule punloadedmap = null;
    printf("call:    vmmdll_map_getunloadedmoduleu #1\n");
    result = vmmdll_map_getunloadedmoduleu(dwpid, null, &cbunloadedmap);
    if(result) {
        printf("success: vmmdll_map_getunloadedmoduleu #1\n");
        printf("         bytecount = %i\n", cbunloadedmap);
    } else {
        printf("fail:    vmmdll_map_getunloadedmoduleu #1\n");
        return 1;
    }
    punloadedmap = (pvmmdll_map_unloadedmodule)localalloc(0, cbunloadedmap);
    if(!punloadedmap) {
        printf("fail:    outofmemory\n");
        return 1;
    }
    printf("call:    vmmdll_map_getunloadedmoduleu #2\n");
    result = vmmdll_map_getunloadedmoduleu(dwpid, punloadedmap, &cbunloadedmap);
    if(!result) {
        printf("fail:    vmmdll_map_getunloadedmoduleu #2\n");
        return 1;
    }
    if(punloadedmap->dwversion != vmmdll_map_unloadedmodule_version) {
        printf("fail:    vmmdll_map_getunloadedmoduleu - bad version\n");
        return 1;
    }
    {
        printf("success: vmmdll_map_getunloadedmoduleu #2\n");
        printf("         module_name                                 base             size\n");
        printf("         =================================================================\n");
        for(i = 0; i < punloadedmap->cmap; i++) {
            printf(
                "         %-40.40s %s %016llx %08x\n",
                punloadedmap->pmap[i].usztext,
                punloadedmap->pmap[i].fwow64 ? "32" : "  ",
                punloadedmap->pmap[i].vabase,
                punloadedmap->pmap[i].cbimagesize
            );
        }
        localfree(punloadedmap);
        punloadedmap = null;
    }


    // retrieve the module of explorer.exe by its name. note it is also possible
    // to retrieve it by retrieving the complete module map (list) and iterate
    // over it. but if the name of the module is known this is more convenient.
    // this required that the peb and ldr list in-process haven't been tampered
    // with ...
    printf("------------------------------------------------------------\n");
    printf("# get module by name 'explorer.exe' in 'explorer.exe'.      \n");
    showkeypress();
    printf("call:    vmmdll_map_getmodulefromnameu\n");
    vmmdll_map_moduleentry moduleentryexplorer;
    result = vmmdll_map_getmodulefromnameu(dwpid, "explorer.exe", &moduleentryexplorer, null);
    if(result) {
        printf("success: vmmdll_map_getmodulefromnameu\n");
        printf("         module_name                                 base             size     entry\n");
        printf("         ======================================================================================\n");
        printf(
            "         %-40.40s %i %016llx %08x %016llx\n",
            "explorer.exe",
            moduleentryexplorer.fwow64 ? 32 : 64,
            moduleentryexplorer.vabase,
            moduleentryexplorer.cbimagesize,
            moduleentryexplorer.vaentry
        );
    } else {
        printf("fail:    vmmdll_map_getmodulefromnameu\n");
        return 1;
    }
