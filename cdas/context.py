import json
import numpy as np
import reportlab.platypus as platy
from reportlab.lib.styles import getSampleStyleSheet
import drawSvg as draw


class Country:
    """
    Used to represent a country and its attributes.

    Attributes
    ----------
    id : int
    name: str
    coordinates : str
        Lat/long coordinates calculated from the map matrix
    total_area : str
        Area within the country's borders in sq km
    land_area : str
    water_area : str
    land_boundary : str
    neighbors : dict
        IDs of neighboring countries and their border in km
    coastline : str
    climate : str
    terrain : str
    natural_hazards : list
    natural_resources : list
    population : str
    nationality : str
    gdp : str
    agriculture : list
    industries : list
    exports : list
    imports : list
    government_type : str
    national_symbol : str
    national_colors : list
    ethnic_groups : dict
        ethnic groups with their % of population
    languages : dict
        languages with their % of population
    religions : dict
        religions with their % of population
    broadband_subscriptions : str
    internet_users : str
    mobile_subscriptions : str
    internet_country_code : str
    military_and_security_forces : str
    waterways : str
    pipelines : list
    ports_and_terminals : dict
    number_of_airports : str
    international_disputes : str

    Methods
    -------
    save(directory, filetype)
        Saves the country attributes to a file of [filetype] in [directory].
    """

    countryCount = -1

    def __init__(self, choices=None, map_matrix=None, **kwargs):
        """
        Parameters
        ----------
        choices : dict
            json dict with values to use as options for geopolitical context
        map_matrix : numpy matrix
            Taken from the Map object
        kwargs : dict
            custom attributes and values for the country
        """

        Country.countryCount += 1
        self.id = Country.countryCount

        if len(kwargs) > 0:
            # We're given country attributes
            self.__dict__.update(kwargs)
        else:
            # We're not given country attributes, generate random countries
            self.name = markov_name()

            # Geographic attributes
            coords = np.where(map_matrix == self.id)
            center = [np.mean(coords[0]), np.mean(coords[1])]
            lat_scale = 180 / map_matrix.shape[0]
            long_scale = 180 / map_matrix.shape[1]
            lat = 90 - center[0] * lat_scale - lat_scale/2
            if np.isnan(lat):
                print(self.id, coords, center)
                print(map_matrix)
            lon = 90 - center[1] * long_scale - long_scale/2
            if lat < 0:
                lat = str(int(abs(lat))) + " 00 S, "
            else:
                lat = str(int(lat)) + " 00 N, "
            if lon < 0:
                lon = str(int(abs(lon))) + " 00 E"
            else:
                lon = str(int(lon)) + " 00 W"
            self.coordinates = lat + lon

            area_multiple = 100000
            area = np.count_nonzero(map_matrix == self.id) * area_multiple
            water = area * np.random.beta(1, 25)  # random percentage of area
            self.total_area = "{:,}".format(area) + " sq km"

            land = area - water
            self.land_area = "{:,}".format(int(land)) + ' sq km'

            self.water_area = "{:,}".format(int(water)) + ' sq km'

            neighbor_spaces = []
            for space in np.argwhere(map_matrix == self.id).tolist():
                top, bottom = [space[0] - 1, space[1]], [space[0]+1, space[1]]
                left, right = [space[0], space[1] - 1], [space[0], space[1]+1]
                if left[1] < 0:
                    left[1] = map_matrix.shape[1]-1
                if right[1] > map_matrix.shape[1] - 1:
                    right[1] = 0
                if top[0] < 0:
                    top[0] = map_matrix.shape[0] - 1
                if bottom[0] > map_matrix.shape[0] - 1:
                    bottom[0] = 0
                for n in [left, right, top, bottom]:
                    if map_matrix[n[0], n[1]] != self.id:
                        neighbor_spaces.append(n)
            neighbors = {}
            coastline = 0
            for n in neighbor_spaces:
                neighbor = map_matrix[n[0], n[1]]
                if neighbor == -1:
                    coastline += 1
                elif neighbor != self.id:
                    try:
                        neighbors[neighbor] += 1
                    except KeyError:
                        neighbors[neighbor] = 1
            coastline = coastline * np.sqrt(area_multiple)
            l_bound = 0
            for n in neighbors:
                v = neighbors[n] * np.sqrt(area_multiple)
                l_bound += v
                neighbors[n] = "{:,}".format(int(v)) + " km"
            self.land_boundary = "{:,}".format(int(l_bound)) + " km"
            self.neighbors = neighbors

            self.coastline = "{:,}".format(int(coastline)) + " km"

            # Calculate the climate zone
            min_lat = min(np.where(map_matrix == self.id)[0])
            max_lat = max(np.where(map_matrix == self.id)[0])
            min_lat_deg = int(90 - min_lat*lat_scale - lat_scale/2)
            max_lat_deg = int(90 - max_lat*lat_scale - lat_scale/2)
            if abs(max_lat_deg) < abs(min_lat_deg):
                # northern hemisphere; switch max and min
                min_lat_deg = int(90 - max_lat*lat_scale - lat_scale/2)
                max_lat_deg = int(90 - min_lat*lat_scale - lat_scale/2)
            zone = []
            for z in choices['climate']['zones']:
                z_min, z_max = choices['climate']['zones'][z]
                if abs(min_lat_deg) <= z_max and abs(min_lat_deg) >= z_min:
                    zone.append(z)
                    continue
                if abs(max_lat_deg) <= z_max and abs(max_lat_deg) >= z_min:
                    zone.append(z)
                if len(zone) > 0 and z_max <= abs(max_lat_deg):
                    zone.append(z)
            self.climate = ', '.join(zone)
            if len(self.climate) == 0:
                print(min_lat_deg, max_lat_deg)

            self.terrain = str(np.random.choice(choices['terrain']))
            if coastline == 0:
                # if country doesn't have coast, but terrain lists it
                while "coast" in self.terrain:
                    self.terrain = str(np.random.choice(
                        choices['terrain']))
            if self.climate == 'Dry':
                self.terrain += '; desert'

            # Geography - natural hazards
            nh = []
            time_desc = ['', 'occasional ', 'frequent ', 'periodic ', 'rare ']
            if "volcan" in self.terrain:
                nh.append(np.random.choice(time_desc) + "volcanic activity")
            if "desert" in self.terrain:
                nh.append(np.random.choice(time_desc) + "sand storms")
            if "Dry" in self.climate:
                nh.append(np.random.choice(time_desc) + "drought")
            if "coast" in self.terrain and "tropical" in self.climate.lower():
                nh.append(np.random.choice(time_desc) + "tropical cyclones")
            if "coast" in self.terrain and self.climate == "Temperate":
                nh.append(np.random.choice(time_desc) + "hurricanes")
            if coastline >= int(l_bound + coastline) / 3:
                if np.random.choice([0, 1]) and "olar" not in self.terrain:
                    nh.append(np.random.choice(time_desc) + "tsunamis")
            if "coast" not in self.terrain and "mountain" not in self.terrain:
                if self.climate != "Polar":
                    nh.append(np.random.choice(time_desc) + "flooding")
            if any(word in self.terrain.lower() for word in
                    ['dry', 'arid', 'desert', 'forest', 'grass']):
                nh.append(np.random.choice(time_desc) + "brush fires")
            if "plain" in self.terrain:
                if np.random.choice([0, 1], p=[.8, .2]) == 1:
                    nh.append(np.random.choice(time_desc) + "tornadoes")
            if "mountain" in self.terrain:
                if np.random.choice([0, 1]) == 1:
                    nh.append(np.random.choice(time_desc) + "earthquakes")
            if "high mountains" in self.terrain:
                nh.append(np.random.choice(time_desc) + "avalanches")
            if "olar" in self.climate or "high mountains" in self.terrain:
                if np.random.choice([0, 1]) == 1:
                    nh.append(np.random.choice(time_desc) + "blizzards")
            if "earthquakes" in [
                    item for hazard in nh
                    for item in hazard.split(' ')]:
                if np.random.choice([0, 1]) == 1:
                    nh.append(np.random.choice(time_desc) + "landslides")
            if len(nh) == 0:
                self.natural_hazards = "None"
            else:
                self.natural_hazards = nh

            num_resources = area/area_multiple + np.random.randint(4, 10)
            if "coast" in self.terrain:
                self.natural_resources = list(np.random.choice(
                    choices['resources']['coast'] +
                    choices['resources']['land'],
                    int(num_resources), replace=False))
            else:
                self.natural_resources = list(np.random.choice(
                    choices['resources']['land'],
                    int(num_resources), replace=False))

            # Create Population
            population = int((np.random.beta(2, 5) * 100) ** 5)
            self.population = "{:,}".format(population)

            # Create nationality
            if self.name.endswith('a'): nationality = self.name+"n(s)"
            elif self.name.endswith('e'): nationality = self.name+"nese"
            elif self.name.endswith('i'): nationality = self.name+"an(s)"
            elif self.name.endswith('o'): nationality = self.name[:-1]+"ani"
            elif self.name.endswith('y'): nationality = self.name[:-1]+"ian(s)"
            else: nationality = self.name + "ian(s)"
            self.nationality = nationality

            # Create GDP based on population
            self.gdp = "$" + "{:,}".format(
                population * np.random.randint(1, 100))

            # Create list of agriculture products based on climate and area
            ag_opts = []
            for climate in self.climate.split(', '):
                ag_opts.extend(choices['agriculture'][climate])
            if coastline > 0:
                ag_opts.extend(choices['agriculture']["Coast"])
            self.agriculture = list(np.random.choice(
                list(set(ag_opts)),
                np.random.randint(2, area/area_multiple + 4), False))
            self.industries = list(np.random.choice(
                choices['eximports'], np.random.randint(3, 12), False))
            self.exports = list(np.random.choice(
                choices['eximports'] + self.agriculture +
                self.natural_resources, np.random.randint(3, 11), False))
            everything = choices['eximports']
            for res in choices['resources']:
                everything.extend(choices['resources'][res])
            for ag in choices['agriculture']:
                everything.extend(choices['agriculture'][ag])
            self.imports = list(np.random.choice(
                [imp for imp in everything if imp not in [
                    self.exports + self.agriculture + self.natural_resources]],
                np.random.randint(3, 11), False))

            # Create government data
            self.government_type = str(np.random.choice(choices['gov types']))
            self.national_symbol = str(np.random.choice(choices['animals']))
            self.national_colors = list(np.random.choice(
                choices['colors'], np.random.randint(2, 4), False))

            # Create Societal data - Ethnic groups
            self.ethnic_groups = {}
            percents = []
            num_groups = int(np.random.beta(2, 2) * 12)
            while len(percents) < num_groups - 1:
                amount_left = 100 - (num_groups-len(percents)) - sum(percents)
                percents.append(np.random.randint(1, amount_left + 1))
            percents.append(100 - sum(percents))
            percents.sort()
            for p in range(len(percents) - 1, -1, -1):
                percent = str(percents[p]) + "%"
                if num_groups == 1:
                    self.ethnic_groups[str(self.id)] = percent
                elif p == num_groups - 1 and np.random.choice(
                        [0, 1], p=[.2, .8]):
                    # if this is the first group, maybe label it the country
                    self.ethnic_groups[str(self.id)] = percent
                elif p == 0 and np.random.choice([0, 1], p=[0.35, 0.65]):
                    # if this is the last group, maybe label it "other"
                    self.ethnic_groups['Other'] = percent
                else:
                    neighbors = [
                        n for n in list(self.neighbors.keys())
                        if str(n) not in self.ethnic_groups.keys()]
                    not_neighbors = [n for n in list(
                        range(0, np.amax(map_matrix) + 1))
                        if n not in neighbors
                        and str(n) not in self.ethnic_groups.keys()]
                    g = np.random.choice([0, 1, 2], p=[0.5, 0.1, 0.4])
                    if g == 0:
                        # ethnic group from a neighboring country
                        if len(neighbors) > 0:
                            self.ethnic_groups[str(np.random.choice(
                                neighbors))] = percent
                        else:
                            self.ethnic_groups[str(np.random.choice(
                                not_neighbors))] = percent
                    elif g == 1:
                        # ethnic group from a non-neighboring country
                        self.ethnic_groups[str(np.random.choice(
                                not_neighbors))] = percent
                    else:
                        # indigenous ethnic group
                        self.ethnic_groups[
                            markov_name(nationality=True) +
                            " (indigenous)"] = percent

            # Create Societal data - languages
            self.languages = {}
            percents = []
            num_groups = np.ceil(np.random.chisquare(4) + 1)
            while len(percents) < num_groups-1:
                amount_left = 100 - (num_groups-len(percents)) - sum(percents)
                percents.append(np.random.randint(1, amount_left + 1))
            percents.append(100 - sum(percents))
            percents.sort()
            for p in range(len(percents) - 1, -1, -1):
                percent = str(percents[p]) + "%"
                if num_groups == 1:
                    self.languages[str(self.id)] = percent
                elif p == num_groups - 1 and np.random.choice(
                        [0, 1], p=[0.2, 0.8]):
                    # if this is the first group, maybe label it the country
                    self.languages[str(self.id)] = percent
                elif p == 0 and np.random.choice([0, 1], p=[0.35, 0.65]):
                    # if this is the last group, maybe label it "other"
                    self.languages['Other'] = percent
                else:
                    egs = [
                        eg for eg in self.ethnic_groups
                        if eg not in self.languages]
                    if 'Other' in egs:
                        egs.remove('Other')
                    if len(egs) > 0:
                        # language from one of the ethnic groups
                        lang = egs[0]
                        self.languages[lang] = percent
                    else:
                        lang = markov_name()
                        if lang.endswith(('a', 'e', 'i', 'o', 'u')):
                            lang += "nese (indigenous)"
                        else:
                            lang += 'ish (indigenous)'
                        self.languages[lang] = percent

            # Create Societal data - religions
            self.religions = {}
            percents = []
            num_groups = int(np.random.beta(2, 2) * 8)
            while len(percents) < num_groups-1:
                amount_left = 100 - (num_groups-len(percents)) - sum(percents)
                percents.append(np.random.randint(1, amount_left + 1))
            percents.append(100 - sum(percents))
            percents.sort()
            religions = np.random.choice(
                list(choices['religions'].keys()), len(percents),
                replace=False, p=list(choices['religions'].values()))
            for r, rel in enumerate(religions):
                self.religions[rel] = str(percents[len(percents) - r-1]) + "%"

            # Create Communications data
            bb = int(population * (np.random.randint(1, 60) / 100))
            self.broadband_subscriptions = "{:,}".format(bb)
            intnet = int(population * (np.random.randint(1, 100) / 100))
            self.internet_users = "{:,}".format(intnet)
            mob = int(population * (1 - np.random.gamma(5, .1)))
            self.mobile_subscriptions = "{:,}".format(mob)
            self.internet_country_code = "." + self.name[:2].lower()

            # Military and security data
            if self.government_type == "non-self-governing territory":
                forces = "No regular military forces; the [COUNTRY] \
                    Government controls foreign and defense policy"
            else:
                forces = str(np.random.choice([
                    f"{self.name} Armed Forces ({self.name[0]}AF): ",
                    f"{self.name} Defense Force ({self.name[0]}DF): ",
                    f"Armed Forces of {self.name} (AF{self.name[0]}): ",
                    f"No regular military forces"], p=[.31, .32, .31, 0.06]))
            if "No regular military forces" in forces:
                force_list = [
                    "National Police Force", "Public Security Forces",
                    "Presidential Guard", "Reserve Force"]
                forces += "; " + ', '.join(list(np.random.choice(
                    force_list, np.random.randint(1, 4), False)))
            else:
                force_list = choices['forces']
                if coastline != 0:
                    force_list = choices['forces'] + [
                        "Navy", "Coast Guard", "Marine Forces"]
                forces += ', '.join(list(np.random.choice(
                    force_list, np.random.randint(2, 6), False)))
            if l_bound == 0 and "Border Guard" in forces:
                if forces.endswith("Border Guard"):
                    forces = forces.replace(", Border Guard", '')
                else:
                    forces = forces.replace("Border Guard, ", '')
            force_list = ["", "; Rapid Reaction Police (paramilitary)", "; \
                Ministry of Interior: General Directorate of National \
                Security", "; Ministry of Intelligence: Directorate of \
                Foreign Military Affairs"]
            forces += str(np.random.choice(force_list, p=[.55, .15, .15, .15]))
            self.military_and_security_forces = forces

            # Transportation data - Water ways
            self.waterways = "{:,}".format(
                np.random.randint(0, water * 2)) + " km"

            # Transportation data - Pipelines
            self.pipelines = []
            p_total = int(np.random.beta(2, 4) * 10000)
            self.pipelines.append("{:,}".format(int(p_total/2)) + " km oil")
            self.pipelines.append("{:,}".format(
                int(3*p_total/8)) + " km refined products")
            self.pipelines.append("{:,}".format(int(p_total/8)) + " km gas")

            # Transportation data - Ports and Terminals
            self.ports_and_terminals = {}
            if coastline > 0:
                p1, p2, p3 = [], [], []
                while len(p1) < (coastline / np.sqrt(area_multiple)):
                    p1.append(markov_name())
                    p2.append(markov_name())
                    p3.append(markov_name())
                self.ports_and_terminals["major seaport(s)"] = ", ".join(p1)
                self.ports_and_terminals["container port(s)"] = ", ".join(p2)
                self.ports_and_terminals["cruise port(s)"] = ", ".join(p3)
            if "natural gas" in self.natural_resources:
                p1 = []
                while len(p1) < area/area_multiple:
                    p1.append(markov_name())
                self.ports_and_terminals[
                    "LNG terminal(s) (export)"] = ", ".join(p1)
            if "natural gas" in self.imports:
                p1 = []
                while len(p1) < area/area_multiple:
                    p1.append(markov_name())
                self.ports_and_terminals[
                    "LNG terminal(s) (import)"] = ", ".join(p1)
            if "oil" in self.natural_resources:
                p1 = []
                while len(p1) < area/area_multiple:
                    p1.append(markov_name())
                self.ports_and_terminals[
                    "Oil terminal(s) (export)"] = ", ".join(p1)
            if "oil" in self.imports:
                p1 = []
                while len(p1) < area/area_multiple:
                    p1.append(markov_name())
                self.ports_and_terminals[
                    "Oil terminal(s) (export)"] = ", ".join(p1)
            if int(self.waterways[:-3].replace(",", '')) > 500:
                p1 = []
                while len(p1) < round(
                        int(self.waterways[:-3].replace(",", '')) / 1000):
                    p1.append(markov_name())
                self.ports_and_terminals["river port(s)"] = ", ".join(p1)
            if water > 500:
                p1 = []
                while len(p1) < round(water / 1000):
                    p1.append(markov_name())
                self.ports_and_terminals["lake port(s)"] = ", ".join(p1)

            # Transportation data - Number of Airports
            self.number_of_airports = "{:,}".format(
                int(land / (np.random.chisquare(1) * area_multiple)))

            # Create Disputes data
            self.international_disputes = "TODO"

    def save(self, directory, filetype):
        """Saves the attributes of the Country to a specified file.

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


class Map:
    """
    Used to represent a world map.

    Attributes
    ----------
    map : numpy matrix
        A representation of the map where each value in the matrix
        corresponds with a country. Ocean is represented as '-1'.

    Methods
    -------
    plot_map(directory, **country_names)
        Saves the map as a SVG in [directory].
    """
    def __init__(self, num_countries):
        """
        Parameters
        ----------
        num_countries : int
            The number of countries to generate for the random world.
        """

        # start by filling a matrix of "ocean" space
        r_scale = np.ceil(np.sqrt(num_countries * 1.5))
        c_scale = 2 * r_scale
        map_matrix = np.full((int(r_scale), int(c_scale)), -1)

        for i in range(0, num_countries):

            # Check if ocean space is still at least 50% of the map
            if map_matrix.size/2 > np.count_nonzero(map_matrix == -1):
                # Add ocean space if map is less than 50% ocean
                ocean_r = np.full((1, len(map_matrix[1, :])), -1)
                temp_map = np.concatenate((ocean_r, map_matrix), axis=0)
                ocean_c = np.full((len(temp_map[:, 1]), 1), -1)
                map_matrix = np.concatenate(
                    (ocean_c, ocean_c, temp_map), axis=1)

            # find the ocean space left and group into contigous spaces
            contiguous = []
            for x in range(0, map_matrix.shape[0]):
                for y in range(0, map_matrix.shape[1]):
                    if map_matrix[x, y] == -1:
                        if len(contiguous) == 0:
                            contiguous.append([(x, y)])  # place first value
                            continue
                        cont = False
                        for n in [(x, y-1), (x, y+1), (x-1, y), (x+1, y)]:
                            if n[0] < 0 or n[0] > map_matrix.shape[0] - 1:
                                continue
                            if n[1] < 0 or n[1] > map_matrix.shape[1] - 1:
                                continue
                            if n[0] == x and n[1] == y:
                                continue
                            if map_matrix[n[0], n[1]] != -1:
                                continue
                            for c in contiguous:
                                if n in c and (x, y) not in c:
                                    c.append((x, y))
                                    cont = True
                                    break
                        if cont is False:
                            contiguous.append([(x, y)])

            # combine groups with shared elements
            ocean = [contiguous[0]]
            for lst in contiguous[1:]:
                cont = False
                for group in ocean:
                    shared = set(lst).intersection(group)
                    if len(shared) > 0:
                        cont = True
                        group.extend([e for e in lst if e not in shared])
                if cont is False:
                    ocean.append(lst)

            # Choose the area for the new country randomly
            area = np.ceil(np.random.chisquare(2))
            # Find the smallest available group that is big enough for the area
            if max([len(g) for g in ocean]) < area:
                # Not enough spaces in any of the avaialble ocean groups to
                #   keep an area this size. Expand the map and return to start
                ocean_r = np.full((1, len(map_matrix[1, :])), -1)
                temp_map = np.concatenate((ocean_r, map_matrix), axis=0)
                ocean_c = np.full((len(temp_map[:, 1]), 1), -1)
                map_matrix = np.concatenate(
                    (ocean_c, ocean_c, temp_map), axis=1)
                i -= 1
                continue

            land = []
            for group in sorted(ocean, key=len):
                if len(group) >= area:
                    land.append(group[np.random.randint(0, len(group))])
                    for la in land:
                        opts = [(la[0] - 1, la[1]), (la[0] + 1, la[1]),
                                (la[0], la[1] - 1), (la[0], la[1] + 1)]
                        np.random.shuffle(opts)
                        for n in opts:
                            if len(land) >= area:
                                continue
                            if n in group and n not in land:
                                land.append(n)
                                break
                    for space in land:
                        map_matrix[space[0], space[1]] = i
                    break

        # add ocean border to top, bottom, left and right if not there already
        # checking each border individually because numpy doesn't allow
        #   changing matrices in place
        if np.count_nonzero(map_matrix[0] != -1) != 0:
            ocean_top = np.full((1, len(map_matrix[1, :])), -1)
            temp_map = np.concatenate((ocean_top, map_matrix), axis=0)
        else:
            temp_map = map_matrix
        if np.count_nonzero(temp_map[len(temp_map[:, 1]) - 1] != -1) != 0:
            ocean_bottom = np.full((1, len(temp_map[1, :])), -1)
            map_matrix = np.concatenate((temp_map, ocean_bottom), axis=0)
        else:
            map_matrix = temp_map
        if np.count_nonzero(map_matrix[:, [0]] != -1) != 0:
            ocean_left = np.full((len(map_matrix[:, 1]), 1), -1)
            temp_map = np.concatenate((ocean_left, map_matrix), axis=1)
        else:
            temp_map = map_matrix
        if np.count_nonzero(temp_map[:, [len(temp_map[1, :]) - 1]] != -1) != 0:
            ocean_right = np.full((len(temp_map[:, 1]), 1), -1)
            map_matrix = np.concatenate((temp_map, ocean_right), axis=1)
        else:
            map_matrix = temp_map

        self.map = map_matrix

    def plot_map(self, directory, **country_names):
        """Converts map matrix to SVG and saves in [directory].

        Country id numbers in matrix will be replaced with names if 
        [country_names] is specified.

        Parameters
        ----------
        directory : str
            Path to save map SVG.
        country_names : dict, optional
            Mapping of country IDs (in matrix) to country names
        """

        fill_colors = [
            [70, 102, 29], [186, 160, 56], [7, 48, 122], [164, 73, 171],
            [77, 81, 91], [143, 35, 24], [4, 86, 47], [142, 88, 22],
            [83, 28, 131], [129, 145, 99]]
        d = draw.Drawing(self.map.shape[1], self.map.shape[0], origin=(
            0, -1 * self.map.shape[0]), displayInline=False,
            style="background-color:dodgerblue")
        for country_id in range(0, self.map.max()+1):
            color = fill_colors[country_id % 10]
            location = np.transpose(np.where(self.map == country_id))
            for space in location:
                d.append(draw.Rectangle(
                    space[1], -1*(space[0]+1), 1, 1,
                    fill=f'rgb({color[0]},{color[1]},{color[2]})'))

        for country_id in range(0, self.map.max()+1):
            location = np.transpose(np.where(self.map == country_id))
            d.append(draw.Text(
                country_names[str(country_id)], 0.3, location[0][1],
                -1*(location[0][0]+1), fill='white'))
        d.setPixelScale(200)  # Set number of pixels per geometry unit
        d.saveSvg(directory+'map.svg')


def markov_name(nationality=False):
    """Generates fake place names.

    Uses a dictionary of probabilities of letter sequences to generate
    random fake place names. 

    Parameters
    ----------
    nationality : binary, optional
        Whether to convert generated name to a nationality by changing
        the ending (default is False)
    """

    with open('data/markov_probabilities.json', 'r') as f:
        probs = json.load(f)
    f.close()

    letter = np.random.choice(
        list(probs[' '].keys()), p=list(probs[' '].values()))
    letters = [letter]
    while letter != "null":
        next_letter = np.random.choice(
            list(probs[letter].keys()), p=list(probs[letter].values()))
        if next_letter == "null" and len(letters) < 3: continue
        if next_letter == ' ' and len(letters) < 3: continue
        if next_letter == ' ' and ' ' in letters[-3:]: continue
        if next_letter == "null" and ' ' in letters[-3:]: continue
        if next_letter == ' ' and len(letters) > 5: break
        if len(letters) > 11: break
        if next_letter != "null": letters.append(next_letter)
        letter = next_letter
    word = ''.join(letters)

    if nationality:
        if word.endswith('a'): word = word+"ni"
        elif word.endswith('e'): word = word+"nese"
        elif word.endswith('i'): word = word+"ani"
        elif word.endswith('o'): word = word[:-1]+"ani"
        elif word.endswith('y'): word = word[:-1]+"iani"
        else: word = word+"ian"

    return word.title()
