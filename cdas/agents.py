import weakref
import numpy as np
import json
from datetime import date
import reportlab.platypus as platy
from reportlab.lib.styles import getSampleStyleSheet

class ThreatActor:

    ActorCount = -1  # track the number of actors created starting at 0
    __instances = set()

    def __init__(self,stix,nouns,adjectives):

        ThreatActor.ActorCount += 1
        self.id = ThreatActor.ActorCount
        
        # Create the name, but don't reuse nouns/adjs already chosen
        names_taken = [ta.name for ta in ThreatActor.getinstances()]
        adj = np.random.choice(adjectives)
        while adj in [name.split(' ')[0] for name in names_taken]:
            adj = np.random.choice(adjectives)
        noun = np.random.choice(nouns)
        while noun in [name.split(' ')[1] for name in names_taken]:
            noun = np.random.choice(nouns)
        self.name = adj +" "+ noun
        
        self.description = ""

        aliases = [f"APT {1000+self.id}"]
        aliases_taken = []
        for ta in ThreatActor.getinstances():
            aliases_taken.extend(ta.aliases)
        alias = f"{np.random.choice(stix['colors'])} \
            {np.random.choice(stix['animals'])}"
        while alias in aliases_taken:
            alias = f"{np.random.choice(stix['colors'])} \
            {np.random.choice(stix['animals'])}"
        aliases.append(alias)
        self.aliases = aliases
        
        self.first_seen = date.fromordinal(np.random.randint(
            date.today().replace(year=date.today().year-10).toordinal(),
            date.today().toordinal()))
        
        last_seen = date.fromordinal(np.random.randint(
            date.today().replace(year=date.today().year-1).toordinal(),
            date.today().toordinal()))
        while last_seen < self.first_seen:
            last_seen = date.fromordinal(np.random.randint(
            date.today().replace(year=date.today().year-1).toordinal(),
            date.today().toordinal()))
        self.last_seen = last_seen

        self.roles = 'sponsor'

        self.resource_level = "government"

        self.type = str(np.random.choice(stix['threat-actor-type']))

        self.target_sectors = list(np.random.choice(stix['sectors'],np.random.randint(2,4),False))

        motivations = list(np.random.choice(stix['attack-motivation'],
            np.random.randint(2,4),replace=False))
        self.primary_motivation = str(motivations[0])

        sophistication = str(np.random.choice(stix['threat-actor-sophistication']))
        self.sophistication = sophistication
        self.secondary_motivations = motivations[1:]
        self.goals = list(np.random.choice(stix['goals'],np.random.randint(2,4),False))

        self.__instances.add(weakref.ref(self))

    @classmethod
    def getinstances(cls):
        dead = set()
        for ref in cls.__instances:
            obj = ref()
            if obj is not None:
                yield obj
            else:
                dead.add(ref)
        cls.__instances -= dead

    def save(self, directory, filetype):
        """Saves the attributes of the Threat Actor to a specified file.

        Parameters
        ----------
        directory : str
            Path to save output 
        filetype : str
            For output file with country data (json or pdf)

        Raises
        ------
        NotImplementedError
            If unsupported filetype is passed in.
        """

        filename = directory + self.name.replace(' ', '_')
        if filetype == 'json':
            filename += ".json"
            with open(filename, 'w') as f:
                json.dump(vars(self), f)
            f.close()
        elif filetype == 'pdf':
            ss = getSampleStyleSheet()
            pdf = platy.SimpleDocTemplate(filename + ".pdf")
            flowables = []
            flowables.append(platy.Paragraph(self.name, ss['Heading1']))
            for k in vars(self):
                if k == 'id' or k == 'name':
                    continue
                if type(vars(self)[k]) is str or type(vars(self)[k]) is int:
                    p = f"{k.replace('_',' ').title()}: {str(vars(self)[k])}"
                    flowables.append(platy.Paragraph(p, ss['BodyText']))
                elif type(vars(self)[k]) is date:
                    p = f"{k.replace('_',' ').title()}: {str(vars(self)[k])}"
                    flowables.append(platy.Paragraph(p, ss['BodyText']))
                else:
                    p = f"{k.replace('_',' ').title()}:"
                    flowables.append(platy.Paragraph(p, ss['BodyText']))
                    bullets = []
                    for v in vars(self)[k]:
                        p = v
                        if type(vars(self)[k]) is not list:
                            p += ": "+vars(self)[k][v]
                        b = platy.Paragraph(p, ss['Normal'])
                        bullets.append(platy.ListItem(b, leftIndent=35))
                    table = platy.ListFlowable(bullets, bulletType='bullet')
                    flowables.append(table)
            pdf.build(flowables)
        else:
            raise NotImplementedError(
                f"Output file type, {filetype}, not supported")