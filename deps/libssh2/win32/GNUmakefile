#########################################################################
#
## Makefile for building libssh2 (Win32 version - gnu make)
## Use: make -f GNUmakefile [help|all|clean|dev|devclean|dist|distclean|dll|objclean]
##
## Hacked by: Guenter Knauf
#
#########################################################################

# Edit the path below to point to the base of your Zlib sources.
ifndef ZLIB_PATH
ZLIB_PATH = ../../zlib-1.2.6
endif
# since currently always enabled in libssh2_config.h set here too!
WITH_ZLIB = 1

# Edit the path below to point to the base of your OpenSSL package.
ifndef OPENSSL_PATH
OPENSSL_PATH = ../../openssl-1.0.1a
endif

# Edit the var below to set to your architecture or set environment var.
ifndef ARCH
ARCH = w32
endif

# Edit the path below to point to your Distribution folder.
ifndef DISTDIR
DISTDIR	= libssh2-$(LIBSSH2_VERSION_STR)-bin-$(ARCH)
endif
DISTARC	= $(DISTDIR).zip

# Edit the path below to point to your Development folder.
ifndef DEVLDIR
DEVLDIR	= libssh2-$(LIBSSH2_VERSION_STR)-dev-$(ARCH)
endif
DEVLARC	= $(DEVLDIR).zip

# Edit the vars below to change target settings.
TARGET	= libssh2
VERSION	= $(LIBSSH2_VERSION)
COPYR   = (c) $(LIBSSH2_COPYRIGHT_STR)
WWWURL	= http://www.libssh2.org/
DESCR	= libssh2 $(LIBSSH2_VERSION_STR)
#STACK	= 64000

# must be equal to DEBUG or NDEBUG
ifndef DB
	DB	= NDEBUG
	# DB	= DEBUG
endif
# Optimization: -O<n> or debugging: -g
ifeq ($(DB),NDEBUG)
	OPT	= -O2
	OBJDIR	= release
else
	OPT	= -g
	OPT	+= -DLIBSSH2DEBUG
	OBJDIR	= debug
endif

# Include the version info retrieved from libssh2.h
-include $(OBJDIR)/version.inc

ifeq ($(findstring /sh,$(SHELL)),/sh)
CP	= cp -afv
# RM	= rm -f
MD	= mkdir
RD	= rm -fr
DL	= '
DS	= /
else
CP	= copy
RM	= del /q /f 2>NUL
MD	= md 2>NUL
RD	= rd /q /s 2>NUL
XX	=
DS	= $(XX)\$(XX)
endif
# Here you can find a native Win32 binary of the original awk:
# http://www.gknw.net/development/prgtools/awk-20100523.zip
AWK	= awk
ZIP	= zip -qzr9

# The following line defines your compiler.
ifdef METROWERKS
	CC = mwcc
else
	CC = $(CROSSPREFIX)gcc
endif

# Global flags for all compilers
CFLAGS	= $(OPT) -D$(DB) -DWIN32 -DLIBSSH2_WIN32 # -DHAVE_CONFIG_H
ifeq ($(ARCH),w64)
CFLAGS	+= -D_AMD64_
endif

ifdef LINK_STATIC
LDLIBS += $(OPENSSL_PATH)/out/libcrypto.$(LIBEXT) $(OPENSSL_PATH)/out/libssl.$(LIBEXT)
else
LDLIBS += $(OPENSSL_PATH)/out/libeay32.$(LIBEXT) $(OPENSSL_PATH)/out/libssl32.$(LIBEXT)
endif

ifeq ($(CC),mwcc)
LD	= mwld
RC	= mwwinrc
LDFLAGS	= -nostdlib
AR	= $(LD)
ARFLAGS	= -nostdlib -library -o
LIBEXT	= lib
#RANLIB	=
LIBPATH	+= -lr "$(METROWERKS)/MSL" -lr "$(METROWERKS)/Win32-x86 Support"
LDLIBS	+= -lMSL_Runtime_x86.lib -lMSL_C_x86.lib -lMSL_Extras_x86.lib
LDLIBS	+= -lkernel32.lib -luser32.lib -lwsock32.lib
RCFLAGS	=
CFLAGS	+= -nostdinc -gccinc -msgstyle gcc -inline off -opt nointrinsics -proc 586
CFLAGS	+= -ir "$(METROWERKS)/MSL" -ir "$(METROWERKS)/Win32-x86 Support"
CFLAGS	+= -w on,nounused,nounusedexpr # -ansi strict
else
LD	= $(CROSSPREFIX)gcc
RC	= $(CROSSPREFIX)windres
LDFLAGS	= -s -shared -Wl,--out-implib,$(TARGET)dll.a
AR	= $(CROSSPREFIX)ar
ARFLAGS	= -cq
LIBEXT	= a
RANLIB	= $(CROSSPREFIX)ranlib
#LDLIBS	+= -lwsock32
LDLIBS	+= -lws2_32 -lgdi32
RCFLAGS	= -I. -I ../include -O coff -i
CFLAGS	+= -fno-strict-aliasing
CFLAGS	+= -Wall # -pedantic
endif

INCLUDES = -I. -I../include
INCLUDES += -I$(OPENSSL_PATH)/outinc -I$(OPENSSL_PATH)/outinc/openssl

ifdef WITH_ZLIB
	INCLUDES += -I$(ZLIB_PATH)
	LDLIBS += $(ZLIB_PATH)/libz.$(LIBEXT)
endif

CFLAGS	+= $(INCLUDES)

vpath %.c . ../src

# include Makefile.inc to get CSOURCES define
include ../Makefile.inc

OBJECTS	:= $(patsubst %.c,%.o,$(CSOURCES))
OBJS	:= $(addprefix $(OBJDIR)/,$(OBJECTS))
OBJL	= $(OBJS) $(OBJDIR)/$(TARGET).res

all: lib dll

dll: prebuild $(TARGET).dll

lib: prebuild $(TARGET).$(LIBEXT)

prebuild: $(OBJDIR) $(OBJDIR)/version.inc
# libssh2_config.h

test: all
	$(MAKE) -C test -f GNUmakefile
 
$(OBJDIR)/%.o: %.c
#	@echo Compiling $<
	$(CC) $(CFLAGS) -c $< -o $@

$(OBJDIR)/version.inc: ../include/libssh2.h $(OBJDIR)
	@echo Creating $@
	@$(AWK) -f ../get_ver.awk $< > $@

dist: all $(DISTDIR) $(DISTDIR)/readme.txt
	@-$(MD) $(DISTDIR)$(DS)bin
	@-$(CP) ..$(DS)AUTHORS $(DISTDIR)
	@-$(CP) ..$(DS)COPYING $(DISTDIR)
	@-$(CP) ..$(DS)INSTALL $(DISTDIR)
	@-$(CP) ..$(DS)README $(DISTDIR)
	@-$(CP) ..$(DS)RELEASE-NOTES $(DEVLDIR)
	@$(CP) $(TARGET).dll $(DISTDIR)$(DS)bin
	@echo Creating $(DISTARC)
	@$(ZIP) $(DISTARC) $(DISTDIR)/* < $(DISTDIR)/readme.txt

dev: all $(DEVLDIR) $(DEVLDIR)/readme.txt
	@-$(MD) $(DEVLDIR)$(DS)bin
	@-$(MD)$(DEVLDIR)$(DS)include
	@-$(MD) $(DEVLDIR)$(DS)win32
	@-$(CP) ..$(DS)AUTHORS $(DISTDIR)
	@-$(CP) ..$(DS)COPYING $(DISTDIR)
	@-$(CP) ..$(DS)INSTALL $(DEVLDIR)
	@-$(CP) ..$(DS)README $(DEVLDIR)
	@-$(CP) ..$(DS)RELEASE-NOTES $(DEVLDIR)
	@$(CP) $(TARGET).dll $(DEVLDIR)$(DS)bin
	@$(CP) ..$(DS)include$(DS)*.h $(DEVLDIR)$(DS)include
	@$(CP) libssh2_config.h $(DEVLDIR)/include
	@$(CP) *.$(LIBEXT) $(DEVLDIR)/win32
	@echo Creating $(DEVLARC)
	@$(ZIP) $(DEVLARC) $(DEVLDIR)/* < $(DEVLDIR)/readme.txt

distclean: clean
	-$(RD) $(DISTDIR)
	-$(RM) $(DISTARC)

devclean: clean
	-$(RD) $(DEVLDIR)
	-$(RM) $(DEVLARC)

objclean: all
	-$(RD) $(OBJDIR)

testclean: clean
	$(MAKE) -C test -f GNUmakefile clean

clean:
#	-$(RM) libssh2_config.h
	-$(RM) $(TARGET).dll $(TARGET).$(LIBEXT) $(TARGET)dll.$(LIBEXT)
	-$(RD) $(OBJDIR)

$(OBJDIR):
	@$(MD) $@

$(DISTDIR):
	@$(MD) $@

$(DEVLDIR):
	@$(MD) $@

$(TARGET).$(LIBEXT): $(OBJS)
	@echo Creating $@
	@-$(RM) $@
	@$(AR) $(ARFLAGS) $@ $^
ifdef RANLIB
	@$(RANLIB) $@
endif

$(TARGET).dll $(TARGET)dll.a: $(OBJL)
	@echo Linking $@
	@-$(RM) $@
	@$(LD) $(LDFLAGS) $^ -o $@ $(LIBPATH) $(LDLIBS)


$(OBJDIR)/%.res: %.rc
	@echo Creating $@
	@$(RC) $(RCFLAGS) $< -o $@


$(DISTDIR)/readme.txt: GNUmakefile
	@echo Creating $@
	@echo $(DL)This is a binary distribution for Win32 platform.$(DL) > $@
	@echo $(DL)libssh version $(LIBSSH2_VERSION_STR)$(DL) >> $@
	@echo $(DL)Please download the complete libssh package for$(DL) >> $@
	@echo $(DL)any further documentation:$(DL) >> $@
	@echo $(DL)$(WWWURL)$(DL) >> $@

$(DEVLDIR)/readme.txt: GNUmakefile
	@echo Creating $@
	@echo $(DL)This is a development distribution for Win32 platform.$(DL) > $@
	@echo $(DL)libssh version $(LIBSSH2_VERSION_STR)$(DL) >> $@
	@echo $(DL)Please download the complete libssh package for$(DL) >> $@
	@echo $(DL)any further documentation:$(DL) >> $@
	@echo $(DL)$(WWWURL)$(DL) >> $@

help: $(OBJDIR)/version.inc
	@echo $(DL)===========================================================$(DL)
	@echo $(DL)OpenSSL path    = $(OPENSSL_PATH)$(DL)
	@echo $(DL)Zlib path       = $(ZLIB_PATH)$(DL)
	@echo $(DL)===========================================================$(DL)
	@echo $(DL)libssh $(LIBSSH2_VERSION_STR) - available targets are:$(DL)
	@echo $(DL)$(MAKE) all$(DL)
	@echo $(DL)$(MAKE) dll$(DL)
	@echo $(DL)$(MAKE) lib$(DL)
	@echo $(DL)$(MAKE) clean$(DL)
	@echo $(DL)$(MAKE) dev$(DL)
	@echo $(DL)$(MAKE) devclean$(DL)
	@echo $(DL)$(MAKE) dist$(DL)
	@echo $(DL)$(MAKE) distclean$(DL)
	@echo $(DL)$(MAKE) objclean$(DL)
	@echo $(DL)$(MAKE) test$(DL)
	@echo $(DL)===========================================================$(DL)


