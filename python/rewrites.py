#! /usr/bin/env python3
# -*- encoding: utf-8 -*-
# -*- coding: utf-8 -*-

# try to parse and analyze an apache vhost configuration

import os
import sys
import regex as re
import mmap
import hmac
import idna
import random
import itertools
import functools
import collections
import datetime
import argparse
import requests

from urllib.parse import urlparse, urlunparse

colorcodes = ['#04b404', '#0101df']

transtab = {
    'BNP': 'backrefnoplus',
    'C': 'chain',
    'CO': 'cookie',
    'DPI': 'discardpath',
    'E': 'env',
    'F': 'forbidden',
    'G': 'gone',
    'H': 'Handler',
    'L': 'last',
    'N': 'next',
    'NC': 'nocase',
    'NE': 'noescape',
    'NS': 'nosubreq',
    'OR': 'ornext',
    'P': 'proxy',
    'PT': 'passthrough',
    'QSA': 'qsappend',
    'QSD': 'qsdiscard',
    'QSL': 'qslast',
    'R': 'redirect',
    'S': 'skip',
    'T': 'type',
}

statusmsg = {
    True: 'OK',
    False: 'FAILED',
}

redirtype = {
    True: 'redirect',
    False: 'rewrite',
}

def combine(uris, chars = '/'):
    return set(itertools.chain.from_iterable(map(lambda y: [y, y.rstrip(chars)], set(uris))))

def check_rewrite(domain, rule, args, statmsg = statusmsg):
    source, target, *flags = rule
    srcuri = source
    dsturi = target

    if 0 < len(flags):
        flags = flags[0].strip('[]').split(',')
        flags = replaceflags(flags)
    redirect = any(map(lambda flag: 'redirect' in flag.split('='), flags))

    if not(target == '-'):
        parens = re.findall('\([^()]+\)', source, flags=re.VERSION1)
        source = source.strip('^$').strip('?')

        if 0 == len(parens):
            u = urlparse(source)
            if not u.scheme:
                srcuri = urlunparse(('https', domain, source, u.params, u.query, u.fragment))

            u = urlparse(target)
            if not u.scheme:
                s = urlparse(srcuri)
                dsturi = urlunparse((s.scheme, domain, target, u.params, u.query, u.fragment))

            if args.verify:
                try:
                    rq = requests.head(srcuri, timeout=5, allow_redirects=True)
                except:
                    print("Exception Info: {}".format(sys.exc_info()))
                    return

                if redirect:
                    ok = rq.url in combine([dsturi])
                else:
                    ok = rq.url in combine([srcuri])

                # see if it's at least one of the url (src, dst)
                if not ok:
                    ok = rq.url in combine([srcuri, dsturi])

                # try the history
                if not ok:
                    rqhistory = map(lambda rsp: rsp.url, rq.history)
                    if redirect:
                        ok = dsturi in rqhistory
                    else:
                        ok = srcuri in rqhistory

                if not ok and args.notok:
                    print("{}\n  {} to {}".format(srcuri, redirtype[redirect], dsturi))
                    print("  <<-- {}".format(rq.url))
                    print("  <<-- {}".format(list(map(lambda rsp: rsp.url, rq.history))))
                    print("{:6} {}\n .. redirect: {}\n .. {}\n .. {}\n .. {}".format(statmsg[ok], rq.url, redirect, srcuri, dsturi, combine([srcuri, dsturi])))

def replaceflags(flags, table = transtab):
    newflags = []
    for flag in flags:
        _flag, *_values = flag.split('=')
        if _flag in table:
            flag = flag.replace(_flag, table[_flag])
        newflags.append(flag)
    return newflags

def h1(infile):
    basename = os.path.basename(infile)
    root, ext = os.path.splitext(basename)
    return root.replace('_', ':')

def do_output(output, ruleno, redirect = False, secure = True, colors = False):
    if redirect:
        output[1] = "+*{}*+".format(output[1])
    if not secure:
        output[3] = "+*{}*+".format(output[3])
    if colors:
        output = list(map(lambda outp: "{{color:{0}}}{1}{{color}}".format(colorcodes[ruleno % len(colorcodes)], outp), output))
    print("|{}|{}|{}|{}|{}|{}|{}|{}|{}|".format(*output))

def print_rules(rules, args):
    print("|| Id || Redirect || Secure || Condition String || Condition Pattern || Condition Flags || Rewrite Pattern || Rewrite Substitution || Rewrite Flags ||")
    table = str.maketrans(dict.fromkeys('$%{}'))

    colors = args.color
    ruleno = 0

    for _rule in rules:
        rule       = _rule['rule']
        conditions = _rule['conditions']

        redirect   = _rule['redirect']
        secure     = _rule['secure']

        clist = []
        flags = []

        if 3 < len(rule): # exception
            pattern, substitution, *rest, flags = rule
            substitution = list(itertools.chain.from_iterable([[substitution], rest]))
            substitution = ' '.join(substitution)
        elif 3 == len(rule):
            pattern, substitution, flags = rule
            flags = flags.strip('[]').split(',')
        else:
            pattern, substitution = rule
        pattern = pattern.replace(':(', '\:(').replace('{', '\{').replace('*', '\*').replace(')-', ')\-').replace('(/)', '/').replace(']', '\]')
        substitution = substitution.replace('%{', '%\{').replace('${', '$\{').replace('|', '\|')
        flags   = replaceflags(flags, transtab)
        redirect = 'redirect' in list(itertools.chain.from_iterable(list(map(lambda flag: flag.split('='), flags))))

        condflags = ['-']
        if 0 == len(conditions):
            condstring = condpattern = '-'
            output = [ruleno, redirect, secure, condstring, condpattern, ', '.join(condflags), pattern, substitution, ', '.join(flags)]
            do_output(output, ruleno, redirect = redirect, secure = secure, colors = colors)
        else:
            for condition in conditions:
                if 0 == len(condition):
                    condition = ['-']*2

                condflags = ['-']
                if 3 == len(condition):
                    condstring, condpattern, condflags = condition
                    condflags = condflags.strip('[]').split(',')
                    condflags = replaceflags(condflags, transtab)
                else:
                    condstring, condpattern = condition

                t_condstring = ':'.join(list(map(lambda s: s.translate(table), condstring.split(':'))))
                condstring = condstring.replace('|', '\|').replace('{', '\{')
                condpattern = condpattern.replace(':(', '\:(').replace('{', '\{').replace('|', '\|').replace('*', '\*').replace(']', '\]')

                if t_condstring in ['REMOTE_ADDR', 'HTTP_HOST']:
                    items = condpattern.split('.')
                    condpattern = '.'.join(list(map(lambda item: item.strip('^$\\'), items)))
                    if 4 == len(items):
                        if condpattern[0] not in ['=', '!']:
                            condpattern = '=' + condpattern
                output = [ruleno, redirect, secure, condstring, condpattern, ', '.join(condflags), pattern, substitution, ', '.join(flags)]
                do_output(output, ruleno, redirect = redirect, secure = secure, colors = colors)
        ruleno += 1

def expand_options(options):
    pattern, *rest = options
    patterns = pattern.split('/')
    xpatterns = list(map(lambda p: [p] == p.split('|') and [p] or p.strip('()').split('|'), patterns))
    patterns  = list(map(lambda t: '/'.join(t), itertools.product(*xpatterns)))

    parens = re.findall('\(([^()]++)\)', pattern)
    iparens = [i+1 for i, e in enumerate(parens) if not([e] == e.split('|'))]

    new_options = []
    for option in list(itertools.product(patterns, [rest])):
        substitution = option[1].copy()
        replacement  = option[0].split('/')
        for ip in iparens:
            substitution[0] = substitution[0].replace('${}'.format(ip), replacement[ip])
            matches = re.findall('\$([0-9]++)', substitution[0])
            for mtch in matches:
                substitution[0] = substitution[0].replace('${}'.format(mtch), '${}'.format(str(int(mtch)-1)))
        new_options.append([option[0], *substitution])
    return new_options

def expand_conditions(conditions, options):
    _conditions = []
    _newoptions = []

    table = str.maketrans(dict.fromkeys('?!=<>'))
    partbl = str.maketrans(dict.fromkeys('()'))
    for condition in conditions:
        condstring, condpattern, *condflags = condition
        parens = re.findall('\([^()]+\)', condpattern, flags=re.VERSION1)
        iparens = [i+1 for i, e in enumerate(parens) if not([e] == e.split('|'))]

        if condstring in ['%{HTTP_COOKIE}', 'HTTP_COOKIE']:
            cookie, value = condpattern.split('=')
            alternatives = re.split('(?<=\))(?=[(\[])', value, flags=re.VERSION1)

            for idx, alternative in enumerate(alternatives):
                patterns = re.findall('(\(([^()]++|(?1))+\))', alternative, flags=re.VERSION1)
                if patterns and 0 < len(patterns):
                    del alternatives[idx]
                    for pattern in patterns:
                        pattern = list(map(lambda p: p.translate(table), pattern))
                        _, noparens = pattern
                        alters = noparens.split('|')

                        production = list(map(lambda t: ''.join(t), list(itertools.product(alters, alternatives))))
                        if 0 == len(production):
                            _conditions.append(condition)
                        else:
                            for optlist in options:
                                for k, _ in enumerate(optlist):
                                    for alter in alters:
                                        newlist = optlist.copy()
                                        replaced = newlist[k].replace('%{}'.format(idx+1), alter)
                                        matches = re.findall('%([0-9]+)', replaced)

                                        lstappend = not(replaced == newlist[k])
                                        for m in matches:
                                            replaced = replaced.replace('%{}'.format(m), '%{}'.format(str(int(m)-1)))
                                        if lstappend:
                                            newlist[k] = replaced
                                            _newoptions.append(newlist)

                            for condpat in production:
                                openparens = condpat.count('(')
                                closeparens = condpat.count(')')
                                if not openparens == closeparens:
                                    condpat = condpat.translate(partbl)
                                _conditions.append([condstring, '='.join([cookie,condpat]), '[ornext]'])
                            _conditions.append([condstring, '='.join(['sentinel', '__dummy__'])])
                else:
                    _conditions.append(condition)
        else:
            _conditions.append(condition)


    if 0 == len(_newoptions):
        _newoptions = options
    return _conditions, _newoptions


def parseline(lineno, lines, patterns = []):
    decoded = lines[lineno].decode()
    columns = decoded.split()
    current = lineno

    if 0 == len(columns):
        return parseline(lineno+1, lines)
    else:
        if '#' == columns[0]: #ignore comments
            return parseline(lineno+1, lines)
        else:
            columns[0] = columns[0].lower()

    return lineno, lineno+1, columns

def parsecfg(srvid, data, args):
    lines  = data.split(b'\n')
    nlines = len(lines)
    lineno = 0
    isrule = False
    isredirect = False
    servername = None
    patterns = ['rewritecond', 'rewriterule', 'redirect', 'servername', 'serveralias']

    rules  = []
    while lineno < nlines:
        issecure = True
        conditions = []

        try:
            current, lineno, columns = parseline(lineno, lines)
        except IndexError:
            break
        pattern, *options = columns

        if pattern not in patterns:
            continue

        if pattern == 'servername':
            servername = options[0]
        elif pattern == 'serveralias':
            if servername is None:
                servername = options[0]

        if pattern == 'redirect':
            isredirect = Truep
            rules.append({'rule': options, 'conditions': [], 'redirect': isredirect, 'secure': issecure})
        elif pattern == 'rewriterule':
            while options[-1] == '\\':
                continuation = []
                del options[-1]
                current, lineno, continuation = parseline(lineno, lines)
                options = list(itertools.chain.from_iterable([options, continuation]))
            xoptions = expand_options(options)
            check_rewrite(servername, options, args)
            for option in xoptions:
                issecure = not(option[0].startswith('^('))
                rules.append({'rule': option, 'conditions': [], 'redirect': isredirect, 'secure': issecure})
        elif pattern == 'rewritecond':
            conditions.append(list(itertools.chain.from_iterable([options])))

            while not(pattern == 'rewriterule'):
                current, lineno, columns = parseline(lineno, lines)
                pattern, *options = columns
                conditions.append(list(itertools.chain.from_iterable([options])))

            # last one was a 'rewriterule'
            del conditions[-1]

            while options[-1].endswith('\\'):
                continuation = []
                options[-1] = options[-1].rstrip('\\')
                if 0 == len(options[-1]):
                    del options[-1]
                current, lineno, continuation = parseline(lineno, lines)
                options = list(itertools.chain.from_iterable([options, continuation]))

            options = expand_options(options)
#            conditions, options = expand_conditions(conditions, options)
            for option in options:
                issecure = not(option[0].startswith('^('))
                rules.append({'rule': option, 'conditions': conditions, 'redirect': isredirect, 'secure': issecure})

    return rules

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Parse apache's <virtualhost ...> configuration extracting rewrite rules")
    parser.add_argument('-f', '--file', action='append', required=False)
    parser.add_argument('-F', '--files', nargs='+', required=False)
    parser.add_argument('-s', '--stdin', action='store_true', required=False, default=False)
    parser.add_argument('-c', '--color', action='store_true', required=False, default=False)
    parser.add_argument('-v', '--verify', action='store_true', required=False, default=False)
    parser.add_argument('-n', '--notok', action='store_true', required=False, default=False)
    args = parser.parse_args()

    infiles = []
    if args.stdin:
        infiles = [sys.stdin]
    if args.file and 0 < len(args.file):
        infiles = list(map(lambda inp: inp.split(','), args.file))
        infiles = list(itertools.chain.from_iterable(infiles))
    if args.files and 0 < len(args.files):
        infiles.extend(args.files)

    if 0 == len(infiles):
        print("missing file(s)")
        sys.exit(-1)

    for infile in infiles:
        if infile == sys.stdin:
            with os.fdopen(os.dup(sys.stdin.fileno()), 'rb') as infd:
                with mmap.mmap(infd.fileno(), 0, mmap.MAP_PRIVATE) as inmap:
                    fcontent = inmap.read()
        else:
            with open(infile, 'rb') as infd:
                with mmap.mmap(infd.fileno(), 0, mmap.MAP_PRIVATE) as inmap:
                    fcontent = inmap.read()

        rules = parsecfg('apache', fcontent, args)
        sys.exit(0)
        print("h2. {}".format(h1(infile)))
        print_rules(rules, args)
