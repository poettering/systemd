# SPDX-License-Identifier: LGPL-2.1+

systemd_homework_sources = files('''
        home-util.c
        home-util.h
        homework.c
        user-record-util.c
        user-record-util.h
'''.split())

systemd_homed_sources = files('''
        home-util.c
        home-util.h
        homed-bus.c
        homed-bus.h
        homed-home-bus.c
        homed-home-bus.h
        homed-home.c
        homed-home.h
        homed-manager-bus.c
        homed-manager-bus.h
        homed-manager.c
        homed-manager.h
        homed-operation.c
        homed-operation.h
        homed-varlink.c
        homed-varlink.h
        homed.c
        pwquality-util.c
        pwquality-util.h
        user-record-sign.c
        user-record-sign.h
        user-record-util.c
        user-record-util.h
'''.split())

if conf.get('ENABLE_HOMED') == 1
        install_data('org.freedesktop.home1.conf',
                     install_dir : dbuspolicydir)
        install_data('org.freedesktop.home1.service',
                     install_dir : dbussystemservicedir)
        install_data('org.freedesktop.home1.policy',
                     install_dir : polkitpolicydir)
endif
