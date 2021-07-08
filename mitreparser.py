'''
    __G__ = "(G)bd249ce4"
    mitre -> parser
'''

from json import loads, dumps, dump, load
from urllib.request import urlretrieve
from codecs import open as copen
from re import findall
from re import compile as rcompile
from collections import Counter
from os import mkdir, path
from logger import ignore_excpetion
from random import randint
from textwrap import fill as tfill
from ixora import QBIxora

#textwrap_args = {'width': 50, 'replace_whitespace': False, 'break_long_words': True}
#temp_list = []

class MitreParser():
    '''
    mitre parser (it will download pre-attack.json/enterprise-attack.json and parse them)
    '''
    def __init__(self,name):
        '''
        initialize class, make mitrefiles path and have mitre links in the class
        '''
        self.graph = QBIxora(name)
        self.mitrepath = path.abspath(path.join(path.dirname(__file__), 'mitrefiles'))
        if not self.mitrepath.endswith(path.sep):
            self.mitrepath = self.mitrepath+path.sep
        if not path.isdir(self.mitrepath):
            mkdir(self.mitrepath)
        self.preattackjson = {}
        self.enterpriseattackjson = {}
        self.fulldict = {}
        self.usedict = {}
        self.preattackurl = "https://raw.githubusercontent.com/mitre/cti/master/pre-attack/pre-attack.json"
        self.enterpriseattackurl = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
        self.setup(self.mitrepath)


    def setup(self, _path):
        '''
        check if there are enterprise-attack.json and pre-attack.json in the system
        if not, download them and parse them. otehrwise use the once from the system
        '''
        temp_list = {}
        if not path.exists(_path+'enterprise-attack.json') and not path.exists(_path+'pre-attack.json'):
            urlretrieve(self.enterpriseattackurl, _path+"enterprise-attack.json")
            urlretrieve(self.preattackurl, _path+"pre-attack.json")
        with copen(_path+"enterprise-attack.json", encoding='ascii', errors='ignore') as enterprise, copen(_path+"pre-attack.json", encoding='ascii', errors='ignore') as pre:
            self.preattack = pre.read()
            self.enterprise = enterprise.read()
            if path.exists(_path+'hardcoded_usedict.json') and path.exists(_path+'hardcoded_fulldict.json'):
                self.fulldict = load(copen(_path+"hardcoded_fulldict.json"))
                self.usedict = load(copen(_path+"hardcoded_usedict.json"))
            else:
                temp_list['preattack'] = loads(self.preattack)['objects']
                temp_list['enterprise'] = loads(self.enterprise)['objects']
                self.update_dict(temp_list['preattack'], {"collection":"preattack"})
                self.update_dict(temp_list['enterprise'], {"collection":"enterprise"})
                self.fulldict = temp_list['preattack'] + temp_list['enterprise']
                self.usedict = self.finduses()
                dump(self.fulldict, copen(_path+"hardcoded_fulldict.json", 'w'))
                dump(self.usedict, copen(_path+"hardcoded_usedict.json", 'w'))

    def update_dict(self, temp_d, temp_s):
        '''
        update target dict
        '''
        for temp_x in temp_d:
            temp_x.update(temp_s)

    def search_once(self, temp_s, temp_d):
        '''
        search once
        '''
        with ignore_excpetion(Exception):
            for temp_x in temp_s:
                if all((temp_k in temp_x and temp_x[temp_k] == temp_var) for temp_k, temp_var in temp_d.items()):
                    return temp_x
        return None

    def search_in_mitre_and_return(self, temp_s, temp_d, temp_r):
        '''
        fine item and return
        '''
        temp_l = []
        for temp_x in temp_s:
            if all((temp_k in temp_x and temp_x[temp_k] == temp_var) for temp_k, temp_var in temp_d.items()):
                temp_l.append({key:temp_x.get(key) for key in temp_r})
        return temp_l

    def nested_search(self, temp_k, temp_d):
        '''
        needs double check
        '''
        if temp_k in temp_d:
            return temp_d[temp_k]
        for temp_k, temp_var in temp_d.items():
            if isinstance(temp_var, dict):
                result = self.nested_search(temp_k, temp_var)
                if result:
                    return temp_k, result

    def findid(self, temp_s, _print):
        '''
        find by id
        '''
        temp_l = {}
        for temp_x in temp_s[0]:
            if temp_x['type'] == 'attack-pattern':
                if temp_x['id'] not in temp_l:
                    temp_l.update({temp_x['id']:temp_x['name']})
            if isinstance(temp_x['description'], list):
                for temp_d in temp_x['description']:
                    if temp_d['type'] == 'attack-pattern':
                        if temp_d['id'] not in temp_l:
                            temp_l.update({temp_d['id']:temp_d['name']})
        if _print:
            print(dumps(temp_l, indent=4, sort_keys=True))
        return temp_l

    def countitem(self, temp_s, temp_k):
        '''
        count
        '''
        return Counter([temp_d[temp_k] for temp_d in temp_s])

    def finduses(self):
        '''
        find all relationship_type uses value and parse them into hardcoded list
        '''
        temp_l = self.search_in_mitre_and_return(self.fulldict, {'relationship_type':'uses'}, ['source_ref', 'target_ref', 'description', 'collection', 'kill_chain_phases'])
        temp_d = {}
        temp_added = {}
        temp_counter = 0
        for temp_i in temp_l:
            temp_counter += 1
            temp_s = self.search_once(self.fulldict, {'id':temp_i['source_ref']})
            temp_u = self.search_once(self.fulldict, {'id':temp_i['target_ref']})
            temp_xx = None
            temp_xs = None
            with ignore_excpetion(Exception):
                temp_xx = temp_u['external_references'][0]['external_id']
                temp_xs = temp_s['external_references'][0]['external_id']
                if temp_s and temp_u:
                    if temp_d.get(temp_s['type'.lower().rstrip()]):
                        if temp_d[temp_s['type']].get(temp_s['name']) == [] or temp_d[temp_s['type']].get(temp_s['name']):
                            temp_dict_ = {'id':temp_xx, 'name':temp_u['name'], 'type':temp_u['type'], 'collection':temp_i['collection']}
                            if 'kill_chain_phases' in temp_u:
                                temp_dict_.update({'kill_chain_phases':', '.join([_['phase_name'] for _ in temp_u['kill_chain_phases']])})
                            if temp_u['type'] == 'malware' or temp_u['type'] == 'tool':
                                temp_dict_.update({'techniques':[]})
                            else:
                                temp_dict_.update({'description':temp_i['description']})
                            temp_d[temp_s['type']][temp_s['name']]['techniques'].append(temp_dict_)
                        else:
                            temp_dict_ = {}
                            if 'kill_chain_phases' in temp_u:
                                temp_dict_ = {temp_s['name']:{'id':temp_xs,'description':temp_s['description'],'techniques':[{'id':temp_xx, 'name':temp_u['name'], 'type':temp_u['type'], 'description':temp_i['description'], 'collection':temp_i['collection'],'kill_chain_phases':', '.join([_['phase_name'] for _ in temp_u['kill_chain_phases']])}]}}
                            else:
                                temp_dict_ = {temp_s['name']:{'id':temp_xs,'description':temp_s['description'],'techniques':[{'id':temp_xx, 'name':temp_u['name'], 'type':temp_u['type'], 'description':temp_i['description'], 'collection':temp_i['collection']}]}}
                            if 'aliases' in temp_s:
                                temp_dict_[temp_s['name']].update({'aliases':', '.join(temp_s['aliases'])})
                            temp_d[temp_s['type']].update(temp_dict_)
                    else:
                        temp_dict_ = {}
                        if 'kill_chain_phases' in temp_u:
                            temp_dict_ = {temp_s['name']:{'id':temp_xs,'description':temp_s['description'],'techniques':[{'id':temp_xx, 'name':temp_u['name'], 'type':temp_u['type'], 'description':temp_i['description'], 'collection':temp_i['collection'], 'kill_chain_phases':', '.join([_['phase_name'] for _ in temp_u['kill_chain_phases']])}]}}
                        else:
                            temp_dict_ = {temp_s['name']:{'id':temp_xs,'description':temp_s['description'],'techniques':[{'id':temp_xx, 'name':temp_u['name'], 'type':temp_u['type'], 'description':temp_i['description'], 'collection':temp_i['collection']}]}}
                        if 'aliases' in temp_s:
                            temp_dict_[temp_s['name']].update({'aliases':', '.join(temp_s['aliases'])})
                        temp_d.update({temp_s['type'].lower().rstrip():temp_dict_})

        return temp_d

    def findapt(self, apt, _print=False):
        '''
        find an apt group from the hardocded list (Name is case sensitive)
        '''
        temp_x = self.usedict['intrusion-set'][apt]
        temp_c = self.countitem(temp_x, 'collection')
        if _print:
            print(dumps([temp_x, temp_c], indent=4, sort_keys=True))
        return [temp_x, temp_c]

    def listapts(self, _print=False):
        '''
        list all apts from hardocded list
        '''
        temp_x = list(self.usedict['intrusion-set'])
        if _print:
            print(dumps(temp_x, indent=4, sort_keys=True))
        return temp_x

    def findmalware(self, malware, _print=False):
        '''
        find malware from the hardocded list (Name is case sensitive)
        '''
        if malware in self.usedict['malware']:
            temp_x = self.usedict['malware'][malware]
            #temp_c = self.countitem(temp_x, 'collection')
            if _print:
                print(dumps(temp_x, indent=4, sort_keys=True))
            else:
                return temp_x
        return None

    def findtool(self, tool, _print=False):
        '''
        find tool from the hardocded list (Name is case sensitive)
        '''
        if tool in self.usedict['tool']:
            temp_x = self.usedict['tool'][tool]
            #temp_c = self.countitem(temp_x, 'collection')
            if _print:
                print(dumps(temp_x, indent=4, sort_keys=True))
            else:
                return temp_x
        return None

    def findword(self, word, _print=False):
        '''
        search for specific word in the files (case insensitive)
        '''
        temp_x = {}
        pattern = rcompile(r'(^.*%s.*$)' % word, 8|2)
        temp_x['enterpriseattack'] = list(set(findall(pattern, self.enterprise)))
        temp_x['preattack'] = list(set(findall(pattern, self.preattack)))
        if _print:
            print(dumps(temp_x, indent=4, sort_keys=True))
        return temp_x

    def random_color(self):
        rand = lambda: randint(100, 200)
        return '#%02X%02X%02X' % (rand(), rand(), rand())

    def gen_apt_graph(self):
        for apt, value in self.usedict['intrusion-set'].items():
            if apt != value['aliases']:
                search = "{} - {}".format(value['id'],value['aliases'])
            else:
                search = "{}".format(apt)
                
            body = "<b>Aliases:</b> " + value['aliases'] + "<br><hr><b>Description:</b> " + value['description']
            self.graph.add_node(apt,
                           _set= {'header':value['id'],'group':(len(value)%5)+1,'width':10, 'color':'#fce903','body':body},
                           search=search)

            if 'techniques' in value:
                for technique in value['techniques']:
                    if technique['type'] != 'malware' and technique['type'] != 'tool':
                        if 'kill_chain_phases' in technique:
                            body = "<b>Tactics:</b> " if ', ' in technique['kill_chain_phases'] else "<b>Tactic:</b> "
                            body += technique['kill_chain_phases'] + "<br><hr><b>Description: </b>" + technique['description']
                            self.graph.add_node(technique['name'],
                                       _set = {'header':technique['id'],'body':body},
                                       search="{} - {}".format(technique['id'],technique['name']))
                        else:
                            self.graph.add_node(technique['name'],
                                           _set = {'header':technique['id'],'body':technique['description']},
                                           search="{} - {}".format(technique['id'],technique['name']))
                        self.graph.add_edge(apt,technique['name'],{'width':1})
                    else:
                        color = ""
                        if technique['type'] == 'malware':
                            color = "#ff3232"
                        else:
                            color = "#ff1a8c"
                        self.graph.add_node(technique['name'],
                                       _set={'header':self.usedict[technique['type']][technique['name']]['id'],'body':self.usedict[technique['type']][technique['name']]['description'],'color':color},
                                       search="{} - {}".format(technique['id'],technique['name']))
                        self.graph.add_edge(apt,technique['name'],{'width':3})
                        for _technique in self.usedict[technique['type']][technique['name']]['techniques']:
                            if 'kill_chain_phases' in _technique:
                                body = "<b>Tactics:</b> " if ', ' in _technique['kill_chain_phases'] else "<b>Tactic:</b> "
                                body += _technique['kill_chain_phases'] + "<br><hr><b>Description: </b>" + _technique['description']
                                self.graph.add_node(_technique['name'],
                                              _set={'header':_technique['id'],'body':body},
                                              search="{} - {}".format(_technique['id'],_technique['name']))
                            else:
                                self.graph.add_node(_technique['name'],
                                              _set={'header':_technique['id'],'body':_technique['description']},
                                              search="{} - {}".format(_technique['id'],_technique['name']))

                            self.graph.add_edge(technique['name'],_technique['name'],{'width':1})

x = MitreParser("Mitre-Visualizer")
x.gen_apt_graph()
x.graph.create_graph('#ixora-graph',window_title="Mitre-Visualizer", search_title="Search Box",search_msg="Search Mitre DB by APT, Malware, Tool, Attack ID or any word such as linx", copyright_link="https://qeeqbox.com",copyright_msg="Qeeqbox-ixora",tools=['search','tooltip','menu','window'], collide=300,distance=300, data=x.graph.graph,method="file_with_json", save_to="Mitre-Visualizer.html",open_file=True)
