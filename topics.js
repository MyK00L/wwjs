'use strict';
const topics = [
  [
    "crane (bird)",
    "tortoise"
  ],
  [
    "pig farm",
    "poultry farm"
  ],
  [
    "kotatsu",
    "hot-water bottle"
  ],
  [
    "icicle",
    "ice cream"
  ],
  [
    "izakaya",
    "family restaurant (i.e. a restaurant with varied and inexpensive menu options)"
  ],
  [
    "underpants",
    "purse"
  ],
  [
    "volleyball",
    "basketball"
  ],
  [
    "pickled cuttlefish",
    "shaved ice (usually served with flavored simple syrup)"
  ],
  [
    "electric fan",
    "air conditioner"
  ],
  [
    "(corrugated) cardboard",
    "plastic sheet (usu. blue)"
  ],
  [
    "short-distance race",
    "running long jump"
  ],
  [
    "stopwatch",
    "skipping rope"
  ],
  [
    "heatstroke",
    "hangover"
  ],
  [
    "(measuring) ruler",
    "abacus"
  ],
  [
    "refrigerator",
    "cooler box"
  ],
  [
    "riddle",
    "great erudition"
  ],
  [
    "(battery) charger",
    "remote control"
  ],
  [
    "seal (used in lieu of a signature)",
    "driver's license"
  ],
  [
    "skateboard",
    "kick scooter"
  ],
  [
    "(pork) cutlet curry",
    "Thai curry"
  ],
  [
    "eraser",
    "mechanical pencil"
  ],
  [
    "swallow (bird of the Hirundinidae family)",
    "shark fin"
  ],
  [
    "wolf (Canis lupus)",
    "fox (esp. the red fox, Vulpes vulpes)"
  ],
  [
    "pumpkin (Cucurbita sp.)",
    "sweet potato (Ipomoea batatas)"
  ],
  [
    "location where spirits and ghosts allegedly often appear",
    "cliff"
  ],
  [
    "heatstroke",
    "sunburn"
  ],
  [
    "young bird",
    "goldfish (Carassius auratus)"
  ],
  [
    "boiled egg",
    "scrambled eggs"
  ],
  [
    "cola (carbonated soft drink)",
    "melon-flavoured soda"
  ],
  [
    "bitter melon (Momordica charantia)",
    "celery"
  ],
  [
    "avocado (Persea americana)",
    "aloe (esp. arborescens)"
  ],
  [
    "Suica",
    "apple (fruit)"
  ],
  [
    "fortune slip (usu. bought at a shrine)",
    "fortune-telling"
  ],
  [
    "tempura donburi",
    "katsudon"
  ],
  [
    "garlic (Allium sativum)",
    "natto (fermented soybeans)"
  ],
  [
    "eye contact",
    "touching (someone)"
  ],
  [
    "hot spring",
    "large bathhouse with many different services"
  ],
  [
    "coupon",
    "point (of a story, argument, etc.)"
  ],
  [
    "one-liner",
    "one's party piece"
  ],
  [
    "candle",
    "match (contest)"
  ],
  [
    "bank",
    "post office"
  ],
  [
    "fine white noodles served flowing in a small flume",
    "bucket brigade"
  ],
  [
    "tiramisu",
    "Bavarian cream"
  ],
  [
    "matsutake mushroom (Tricholoma matsutake)",
    "truffle"
  ],
  [
    "greengrocer",
    "fish market"
  ],
  [
    "rice cooked with matsutake",
    "chestnut rice"
  ],
  [
    "athletic meet (esp. at a school)",
    "school festival"
  ],
  [
    "washboard",
    "black rotary-dial telephone"
  ],
  [
    "towel",
    "house-cloth"
  ],
  [
    "penguin",
    "yak tail hair"
  ],
  [
    "physical examination",
    "disaster drill"
  ],
  [
    "removal of dissolute sons from the family register (Edo period)",
    "kiwi (Apteryx spp.)"
  ],
  [
    "art museum",
    "museum"
  ],
  [
    "wet wipes",
    "toilet paper"
  ],
  [
    "Chinese-style hot pot",
    "chankonabe"
  ],
  [
    "haiku",
    "poem"
  ],
  [
    "shed",
    "walk-in closet"
  ],
  [
    "baby",
    "kitten"
  ],
  [
    "castanets",
    "cymbal"
  ],
  [
    "sleeping in late",
    "feigned illness"
  ],
  [
    "beautician",
    "bartender"
  ],
  [
    "diamond",
    "platinum (Pt)"
  ],
  [
    "Chinese soft-shelled turtle (Pelodiscus sinensis)",
    "deformity"
  ],
  [
    "manicure",
    "lipstick"
  ],
  [
    "false eyelashes",
    "manicure"
  ],
  [
    "karaoke",
    "bowling (esp. tenpin)"
  ],
  [
    "kotatsu",
    "electric carpet"
  ],
  [
    "mountain climbing",
    "triathlon"
  ],
  [
    "courage",
    "lively"
  ],
  [
    "swim ring",
    "tetrapod"
  ],
  [
    "lake (in place names)",
    "unexplored region"
  ],
  [
    "supplement",
    "umeboshi"
  ],
  [
    "pincers (of a crab, scorpion, etc.)",
    "clothespin"
  ],
  [
    "quiz",
    "riddle"
  ],
  [
    "dental brushing",
    "face-washing"
  ],
  [
    "piano",
    "violin"
  ],
  [
    "topknot (hair style)",
    "Regent hairstyle"
  ],
  [
    "cotton candy",
    "mizuame"
  ],
  [
    "pregnancy",
    "corpulence"
  ],
  [
    "window",
    "counter for beds"
  ],
  [
    "(one's) superior",
    "intimacy"
  ],
  [
    "ice cream soda",
    "caffè latte"
  ],
  [
    "sunflower (Helianthus annuus)",
    "bitter melon (Momordica charantia)"
  ],
  [
    "colored pencil",
    "paint"
  ],
  [
    "cruiser (i.e. warship or cabin cruiser)",
    "mobile home"
  ],
  [
    "full-length marathon",
    "surfing"
  ],
  [
    "taco",
    "hot dog"
  ],
  [
    "fire alarm or sensor",
    "digestive organs"
  ],
  [
    "patrol car",
    "ambulance"
  ],
  [
    "fly (any insect of infraorder Muscomorpha)",
    "mosquito"
  ],
  [
    "mosquito coil",
    "toy fireworks"
  ],
  [
    "parfait",
    "pancake"
  ],
  [
    "band-man (member of a musical band)",
    "bartender"
  ],
  [
    "typhoon",
    "heavy snow"
  ],
  [
    "swallow's nest",
    "sea cucumber (Holothuroidea spp.)"
  ],
  [
    "konnyaku (Amorphophallus konjac)",
    "shirataki noodles"
  ],
  [
    "coffee bean",
    "tea leaf"
  ],
  [
    "picture for coloring in (colouring)",
    "spot the difference (puzzle)"
  ],
  [
    "cherry tomato",
    "umeboshi"
  ],
  [
    "school trip",
    "athletic meet (esp. at a school)"
  ],
  [
    "sunglasses",
    "fake eyeglasses"
  ],
  [
    "bitcoin (cryptocurrency)",
    "dollar"
  ],
  [
    "stone sauna",
    "sauna"
  ],
  [
    "blueberry",
    "inhuman"
  ],
  [
    "public telephone",
    "ticket"
  ],
  [
    "matchstick",
    "writer"
  ],
  [
    "earthenware pot",
    "fireside"
  ],
  [
    "eye test",
    "body measurements"
  ],
  [
    "seersucker",
    "rugby"
  ],
  [
    "crayon",
    "choke (in professional wrestling)"
  ],
  [
    "collection of words or drawings by several people on a single sheet of paper",
    "bunch of flowers"
  ],
  [
    "change of occupation",
    "moving (dwelling, office, etc.)"
  ],
  [
    "Halloween",
    "setsubun"
  ],
  [
    "wasabi (Wasabia japonica)",
    "mustard"
  ],
  [
    "campground",
    "barbecue site"
  ],
  [
    "onigiri",
    "dango"
  ],
  [
    "triangles (used in mechanical drawing)",
    "protractor"
  ],
  [
    "recorder (e.g. tape recorder, time recorder)",
    "melodica"
  ],
  [
    "tonkatsu",
    "fried prawns"
  ],
  [
    "suit (clothing)",
    "leather shoes"
  ],
  [
    "skydiving",
    "paraglider"
  ],
  [
    "railway track",
    "highway"
  ],
  [
    "supplement",
    "energy drink"
  ],
  [
    "research project (e.g. at school)",
    "illustrated diary"
  ],
  [
    "microwave oven",
    "toaster"
  ],
  [
    "rolled Japanese-style omelette",
    "chawanmushi"
  ],
  [
    "softball",
    "baseball"
  ],
  [
    "whale shark (Rhincodon typus)",
    "whale (Cetacea spp.)"
  ],
  [
    "pre-paid card for purchasing books",
    "telephone card"
  ],
  [
    "anemia",
    "(common) cold"
  ],
  [
    "baby",
    "puppy"
  ],
  [
    "wedding dress",
    "wedding hall"
  ],
  [
    "toilet seat with bidet functions",
    "toilet device that plays a melody or flushing sound"
  ],
  [
    "artificial intelligence",
    "blockchain"
  ],
  [
    "blond hair",
    "Buddhist priest"
  ],
  [
    "puzzle",
    "disentanglement puzzle"
  ],
  [
    "empty nest",
    "purse snatching"
  ],
  [
    "forbearance (in the face of difficulty, persecution, etc.)",
    "natto (fermented soybeans)"
  ],
  [
    "Olympics",
    "World Cup (e.g. soccer)"
  ],
  [
    "telescope",
    "microscope"
  ],
  [
    "protective household deity in Tōhoku, appearing as a red-faced child spirit with bobbed hair",
    "fairy"
  ],
  [
    "dishwasher",
    "pressure cooker"
  ],
  [
    "ghostleg lottery",
    "rock-paper-scissors (game)"
  ],
  [
    "balcony",
    "entrance"
  ],
  [
    "onigiri with shrimp tempura filling",
    "(tip section of) chicken wing"
  ],
  [
    "keyboard",
    "headphone"
  ],
  [
    "shampoo",
    "broad-rimmed topless cap worn (esp. by young children) to prevent shampoo getting into one's eyes"
  ],
  [
    "picture book",
    "wooden building blocks"
  ],
  [
    "pro wrestler",
    "competitive eater"
  ],
  [
    "all-you-can-eat",
    "stuffing a shopping container for a fixed price"
  ],
  [
    "electrical outlet",
    "battery"
  ],
  [
    "hick",
    "silent fart"
  ],
  [
    "desperate situation with no escape",
    "by a hair's breadth"
  ],
  [
    "railway station",
    "bus stop"
  ],
  [
    "(cow's) milk",
    "soy milk"
  ],
  [
    "homa",
    "tofu"
  ],
  [
    "tofu",
    "cheese"
  ],
  [
    "pencil case",
    "toolbox"
  ],
  [
    "being Instagrammable",
    "power spot"
  ],
  [
    "tennis",
    "table tennis"
  ],
  [
    "zaru soba (soba served on a bamboo draining basket with dipping sauce)",
    "cold Chinese noodles served with a dipping sauce separately"
  ],
  [
    "Sun",
    "Monday"
  ],
  [
    "unrequited love",
    "disappointed love"
  ],
  [
    "road",
    "back street"
  ],
  [
    "south wind tile",
    "deep-fried food (esp. chicken)"
  ],
  [
    "grassy field",
    "beach"
  ],
  [
    "screw",
    "packing tape"
  ],
  [
    "dumbbell",
    "skipping rope"
  ],
  [
    "folding paper-case",
    "shoji (paper sliding door)"
  ],
  [
    "sliced vegetables pickled in soy sauce",
    "red pickled ginger"
  ],
  [
    "static electricity",
    "pimple"
  ],
  [
    "headache",
    "toothache"
  ],
  [
    "doctor",
    "lawyer"
  ],
  [
    "peeler (for peeling a label from its base in a barcode printer)",
    "scrubbing brush"
  ],
  [
    "magician",
    "swindler"
  ],
  [
    "Japanese leek (Allium chinense)",
    "sliced vegetables pickled in soy sauce"
  ],
  [
    "restaurant that only serves set meals",
    "izakaya"
  ],
  [
    "yoga",
    "running"
  ],
  [
    "dining hall (at a temple)",
    "provision of lunch (e.g. at office, school, etc.)"
  ],
  [
    "curtain",
    "slipper"
  ],
  [
    "aurora",
    "shooting star"
  ],
  [
    "diet",
    "rehabilitation"
  ],
  [
    "mapo tofu (spicy Sichuan dish of tofu and minced meat)",
    "tan tan ramen"
  ],
  [
    "golf",
    "baseball"
  ],
  [
    "illustrator",
    "voice actor or actress (radio, animation, etc.)"
  ],
  [
    "illustrator",
    "beautician"
  ],
  [
    "Rubik's Cube",
    "disentanglement puzzle"
  ],
  [
    "unicycle",
    "stilts (for walking)"
  ],
  [
    "triangles (used in mechanical drawing)",
    "pair of compasses"
  ],
  [
    "alphabet",
    "kanji"
  ],
  [
    "diviner",
    "Catholic priest"
  ],
  [
    "(thick) scarf",
    "(face) mask"
  ],
  [
    "caviar",
    "sea urchin"
  ],
  [
    "sea urchin",
    "salted salmon roe"
  ],
  [
    "salted salmon roe",
    "caviar"
  ],
  [
    "share (in a company)",
    "virtual currency"
  ],
  [
    "crêpe",
    "pancake"
  ],
  [
    "cheating (on an examination)",
    "shoplifting"
  ],
  [
    "fried chicken (esp. American-style)",
    "tonkatsu"
  ],
  [
    "church",
    "mosque"
  ],
  [
    "newsprint",
    "journal"
  ],
  [
    "cream puff",
    "cream-filled roll"
  ],
  [
    "rigid frame",
    "gyudon"
  ],
  [
    "paint",
    "crayon"
  ],
  [
    "aroma oil",
    "incense"
  ],
  [
    "God",
    "space alien"
  ],
  [
    "xylophone",
    "dram (unit of weight)"
  ],
  [
    "hallway slippers",
    "disaster hood"
  ],
  [
    "iron (for pressing clothes)",
    "fry pan"
  ],
  [
    "metal rod",
    "jungle gym"
  ],
  [
    "beer garden",
    "festival"
  ],
  [
    "folk dance",
    "coordinated group gymnastics (in which teams form pyramids or other shapes)"
  ],
  [
    "gas station",
    "drive-through"
  ],
  [
    "hometown tax",
    "final income tax return"
  ],
  [
    "keyboard",
    "mouse (esp. laboratory)"
  ],
  [
    "(wet) compress",
    "adhesive bandage"
  ],
  [
    "stopwatch",
    "alarm clock"
  ],
  [
    "pajamas",
    "sweatshirt"
  ],
  [
    "triumphant pose (assumed by an athlete, etc.)",
    "clenched fist"
  ],
  [
    "space alien",
    "tsuchinoko"
  ],
  [
    "unmarked police car",
    "taxi"
  ],
  [
    "glove",
    "socks"
  ],
  [
    "cheese",
    "yogurt"
  ],
  [
    "newspaper",
    "Turkey"
  ],
  [
    "clay",
    "crayon"
  ],
  [
    "(measuring) ruler",
    "protractor"
  ],
  [
    "escalator",
    "elevator"
  ],
  [
    "sponge",
    "scrubbing brush"
  ],
  [
    "squirrel (any mammal of family Sciuridae)",
    "hamster"
  ],
  [
    "soap",
    "hand soap"
  ],
  [
    "short-distance race",
    "relay"
  ],
  [
    "raw noodles",
    "dried noodles"
  ],
  [
    "mouse",
    "rabbit"
  ],
  [
    "plastic bottle (made of polyethylene terephthalate)",
    "plastic bag"
  ],
  [
    "double-edged eyelid",
    "dimple"
  ],
  [
    "carpet",
    "chandelier"
  ],
  [
    "croissant",
    "horn-shaped pastry with chocolate filling"
  ],
  [
    "slipper",
    "socks"
  ],
  [
    "rug one steps onto from the foyer",
    "carpet"
  ],
  [
    "open-air fire (e.g. for garden refuse)",
    "spring water"
  ],
  [
    "tent",
    "open-air fire (e.g. for garden refuse)"
  ],
  [
    "gas cylinder",
    "Chakaman (brand-name of rechargeable lighter)"
  ],
  [
    "slime",
    "rice cakes"
  ],
  [
    "protractor",
    "pair of compasses"
  ],
  [
    "false tooth",
    "wig"
  ],
  [
    "toothbrush",
    "sponge"
  ],
  [
    "carrying a person in one's arms",
    "carrying (someone) on one's back (esp. a child)"
  ],
  [
    "humming",
    "reading aloud"
  ],
  [
    "chicken or fish meatloaf made with egg",
    "Hamburg steak"
  ],
  [
    "national flag",
    "map"
  ],
  [
    "newsprint",
    "letter"
  ],
  [
    "lemon sour (cocktail)",
    "highball"
  ],
  [
    "finger flick to the forehead",
    "bamboo stick used to strike meditators into greater wakefulness (in Zen Buddhism)"
  ],
  [
    "pepper",
    "salt (e.g. sodium chloride, calcium sulfate, etc.)"
  ],
  [
    "LINE (instant messaging software)",
    "telephone call"
  ],
  [
    "postbox",
    "public telephone"
  ],
  [
    "blackboard",
    "shoe rack (in an entrance)"
  ],
  [
    "yuzu (Citrus ichangensis x C. reticulata)",
    "kabosu (type of citrus fruit) (Citrus sphaerocarpa)"
  ],
  [
    "tent",
    "sleeping bag"
  ],
  [
    "beckoning cat",
    "Seven Gods of Fortune"
  ],
  [
    "Buddhist (household) altar",
    "kamidana"
  ],
  [
    "swing",
    "seesaw"
  ],
  [
    "bungee-jumping",
    "haunted house"
  ],
  [
    "salmon (Salmonidae spp.)",
    "tuna (edible fish, Thunnus spp.)"
  ],
  [
    "softball",
    "volleyball"
  ],
  [
    "report card",
    "body measurements"
  ],
  [
    "matsutake mushroom (Tricholoma matsutake)",
    "Pacific saury (Cololabis saira)"
  ],
  [
    "pretending to be out",
    "feigned illness"
  ],
  [
    "castanets",
    "xylophone"
  ],
  [
    "sparkling wine",
    "champagne"
  ],
  [
    "shooting star",
    "fireworks"
  ],
  [
    "rainbow",
    "shooting star"
  ],
  [
    "salted Pacific cod entrails in spicy sauce",
    "cubed daikon kimchi"
  ],
  [
    "Rubik's Cube",
    "puzzle"
  ],
  [
    "French bread (esp. baguette)",
    "scone"
  ],
  [
    "glasses",
    "contact lens"
  ],
  [
    "police box",
    "(public) park"
  ],
  [
    "(chemical) body warmer",
    "glove"
  ],
  [
    "sun visor",
    "sunglasses"
  ],
  [
    "vacuum cleaner",
    "ventilation fan"
  ],
  [
    "electric fan",
    "ventilation fan"
  ],
  [
    "emotional strength",
    "insight"
  ],
  [
    "(mechanical) stoker",
    "empty nest"
  ],
  [
    "raw egg",
    "natto (fermented soybeans)"
  ],
  [
    "kitchen knife",
    "saw"
  ],
  [
    "nail",
    "hammer"
  ],
  [
    "cushion",
    "sofa"
  ],
  [
    "deep-fried food (esp. chicken)",
    "tonkatsu"
  ],
  [
    "nail (e.g. fingernail, toenail)",
    "eyebrow"
  ],
  [
    "slamming one's hand into the wall in front of someone (e.g. to stop them from leaving; often viewed as romantic)",
    "suddenly lifting someone's face by their chin (in a domineering yet romantic fashion)"
  ],
  [
    "bell cricket (Meloimorpha japonicus)",
    "semi-"
  ],
  [
    "bok choy (Brassica rapa subsp. chinensis; esp. cultivars with white stalks)",
    "cabbage (Brassica oleracea)"
  ],
  [
    "rice seasoning (usu. containing fish meal, seaweed, sesame, etc.)",
    "preserved food boiled in soy"
  ],
  [
    "apple (fruit)",
    "pear (esp. Japanese pear)"
  ],
  [
    "point card",
    "credit card"
  ],
  [
    "Bon Festival dance",
    "radio calisthenics"
  ],
  [
    "running long jump",
    "running high jump"
  ],
  [
    "shot put",
    "discus throw"
  ],
  [
    "meditation (with closed eyes)",
    "half body bathing"
  ],
  [
    "tire",
    "handle"
  ],
  [
    "even monkeys fall from trees",
    "bad things happen to those who attempt things"
  ],
  [
    "skyrocket (firework)",
    "festival"
  ],
  [
    "deep-fried food (esp. chicken)",
    "thick fried tofu"
  ],
  [
    "fine white noodles served flowing in a small flume",
    "watermelon splitting (game)"
  ],
  [
    "firefly (Luciola cruciata)",
    "fireworks"
  ],
  [
    "New Year's gift (usu. money given to a child by relatives and visitors)",
    "birthday present"
  ],
  [
    "roof tile",
    "brick"
  ],
  [
    "family restaurant (i.e. a restaurant with varied and inexpensive menu options)",
    "hardware store"
  ],
  [
    "honey",
    "mizuame"
  ],
  [
    "hand cream",
    "lip balm"
  ],
  [
    "wasabi (Wasabia japonica)",
    "minor festal song (subgenre of the Shi Jing)"
  ],
  [
    "dodgeball",
    "softball"
  ],
  [
    "fish sausage",
    "chicken or fish meatloaf made with egg"
  ],
  [
    "Earth globe (model)",
    "microscope"
  ],
  [
    "prayer",
    "meditation (with closed eyes)"
  ],
  [
    "aroma oil",
    "scented water used for purification"
  ],
  [
    "giving someone a ride on one's shoulders",
    "hug"
  ],
  [
    "point (of a story, argument, etc.)",
    "electronic money"
  ],
  [
    "rice ball coated with sweetened red beans, soybean flour or sesame",
    "wafer cake filled with bean jam"
  ],
  [
    "pyramid",
    "Eiffel Tower"
  ],
  [
    "earphones",
    "smartphone"
  ],
  [
    "mango (Mangifera indica)",
    "papaya (Carica papaya)"
  ],
  [
    "calendar",
    "stopwatch"
  ],
  [
    "bobsleigh",
    "ski jump"
  ],
  [
    "egg boiled, peeled, and steeped in soy sauce marinade",
    "stew of cubed meat or fish (esp. pork belly or tuna)"
  ],
  [
    "sneaker",
    "running shoes"
  ],
  [
    "cheese",
    "cream"
  ],
  [
    "scrawl",
    "flip book"
  ],
  [
    "sleeper train",
    "first-class"
  ],
  [
    "baseball",
    "seersucker"
  ],
  [
    "soda pop (esp. fruit-flavored)",
    "cola (carbonated soft drink)"
  ],
  [
    "American football",
    "basketball"
  ],
  [
    "kendo",
    "fencing"
  ],
  [
    "bench press",
    "squat"
  ],
  [
    "table tennis",
    "arm wrestling"
  ],
  [
    "table tennis",
    "badminton"
  ],
  [
    "sumo wrestling",
    "rugby"
  ],
  [
    "butterfly (swimming stroke)",
    "backstroke (swimming)"
  ],
  [
    "butterfly (swimming stroke)",
    "crawl (swimming)"
  ],
  [
    "regulation baseball (as opposed to the variety played with a rubber ball)",
    "softball"
  ],
  [
    "tempura donburi",
    "onigiri with shrimp tempura filling"
  ],
  [
    "dodgeball",
    "basketball"
  ],
  [
    "American football",
    "basketball"
  ],
  [
    "kabaddi",
    "cricket (game)"
  ],
  [
    "penalty kick",
    "free kick"
  ],
  [
    "bunt",
    "double play"
  ],
  [
    "badminton",
    "tennis"
  ],
  [
    "strength training",
    "running"
  ],
  [
    "trunks",
    "school swimsuit"
  ],
  [
    "skiing",
    "snowball fight"
  ],
  [
    "malathion (insecticide)",
    "swimming"
  ],
  [
    "bouldering",
    "kendo"
  ],
  [
    "grand slam",
    "hat trick"
  ],
  [
    "boat race",
    "keirin"
  ],
  [
    "mouthpiece",
    "(protective) headgear"
  ],
  [
    "triathlon",
    "boxing"
  ],
  [
    "sumo wrestling",
    "arm wrestling"
  ],
  [
    "train",
    "car"
  ],
  [
    "email",
    "letter"
  ],
  [
    "time",
    "money"
  ],
  [
    "excursion",
    "athletic meet (esp. at a school)"
  ],
  [
    "extension cord",
    "source of electricity"
  ],
  [
    "washing (esp. dishes and laundry)",
    "toilet cleaning"
  ],
  [
    "toilet cleaning",
    "washing"
  ],
  [
    "bitcoin (cryptocurrency)",
    "real estate"
  ],
  [
    "prime minister (as the head of a cabinet government)",
    "company president"
  ],
  [
    "grasshopper",
    "praying mantis (esp. the narrow-winged mantis, Tenodera angustipennis)"
  ],
  [
    "smartphone",
    "personal computer"
  ],
  [
    "sea",
    "river"
  ],
  [
    "toilet paper",
    "toilet seat with bidet functions"
  ],
  [
    "ghost",
    "bear (any mammal of family Ursidae)"
  ],
  [
    "Shinkansen",
    "aeroplane"
  ],
  [
    "surfer",
    "lifesaver"
  ],
  [
    "country",
    "mountain"
  ],
  [
    "dustpan",
    "vacuum cleaner"
  ],
  [
    "singing together",
    "karaoke"
  ],
  [
    "magic",
    "extra-sensory perception"
  ],
  [
    "extra-sensory perception",
    "inspiration"
  ],
  [
    "magic",
    "inspiration"
  ],
  [
    "water balloon",
    "water pistol"
  ],
  [
    "angel",
    "fairy"
  ],
  [
    "protective household deity in Tōhoku, appearing as a red-faced child spirit with bobbed hair",
    "angel"
  ],
  [
    "fairy",
    "protective household deity in Tōhoku, appearing as a red-faced child spirit with bobbed hair"
  ],
  [
    "herb",
    "basil"
  ],
  [
    "tobacco",
    "alcohol"
  ],
  [
    "YouTuber",
    "reader model"
  ],
  [
    "sneeze",
    "unlucky day"
  ],
  [
    "sneeze",
    "hiccup"
  ],
  [
    "unlucky day",
    "nodding off (while sitting)"
  ],
  [
    "nodding off (while sitting)",
    "sleeping in late"
  ],
  [
    "paper umbrella",
    "leather boots"
  ],
  [
    "sea",
    "(swimming) pool"
  ],
  [
    "fortune-telling",
    "promise"
  ],
  [
    "jellyfish",
    "plastic bag"
  ],
  [
    "wooden building blocks",
    "sandpit"
  ],
  [
    "hospital",
    "beauty parlour"
  ],
  [
    "classbook",
    "transcript of results"
  ],
  [
    "(swimming) pool",
    "gymnasium"
  ],
  [
    "oil",
    "Wednesday"
  ],
  [
    "rich person",
    "moderately wealthy person"
  ],
  [
    "eye bags",
    "double-edged eyelid"
  ],
  [
    "head of a garden",
    "boss (esp. yakuza)"
  ],
  [
    "toothbrush",
    "cleaning"
  ],
  [
    "New Year (esp. first three days)",
    "spring break"
  ],
  [
    "real estate",
    "stump"
  ],
  [
    "scrubbing brush",
    "house-cloth"
  ],
  [
    "vase used to hold flower offerings (often made of gilded copper)",
    "drainage"
  ],
  [
    "comical (story, song)",
    "music"
  ],
  [
    "dance",
    "music"
  ],
  [
    "division",
    "obtaining the respective numbers of cranes and tortoises from the total of their heads and legs"
  ],
  [
    "manhole",
    "utility pole"
  ],
  [
    "ambulance",
    "taxi"
  ],
  [
    "pigeon",
    "tree sparrow (Passer montanus)"
  ],
  [
    "walk",
    "running"
  ],
  [
    "ornamental (foliage) plant",
    "insectivorous plants"
  ],
  [
    "Othello (board game)",
    "chess"
  ],
  [
    "desk",
    "mirror"
  ],
  [
    "sneaker",
    "boots"
  ],
  [
    "insect cage",
    "vase used to hold flower offerings (often made of gilded copper)"
  ],
  [
    "ornament",
    "garbage can"
  ],
  [
    "air conditioner",
    "(room) heater"
  ],
  [
    "magma",
    "sparks"
  ],
  [
    "washing one's hands",
    "dental brushing"
  ],
  [
    "curtain",
    "mirror"
  ],
  [
    "fat-bodied, small-mouthed earthenware jar for carrying water",
    "cop"
  ],
  [
    "plastic bottle (made of polyethylene terephthalate)",
    "cop"
  ],
  [
    "television",
    "washing machine"
  ],
  [
    "advertisement",
    "signboard"
  ],
  [
    "signboard",
    "sign"
  ],
  [
    "monorail",
    "linear motor train"
  ],
  [
    "convenience store",
    "ramen restaurant"
  ],
  [
    "metal rod",
    "swing"
  ],
  [
    "jungle gym",
    "sandpit"
  ],
  [
    "(wet) compress",
    "sleep mask"
  ],
  [
    "bookshelves",
    "cupboard"
  ],
  [
    "picture",
    "photograph"
  ],
  [
    "empty stomach",
    "potbelly"
  ],
  [
    "diviner",
    "psychic"
  ],
  [
    "public telephone",
    "bench"
  ],
  [
    "water fountain",
    "pond"
  ],
  [
    "closet",
    "shoe rack (in an entrance)"
  ],
  [
    "staying up late",
    "lack of sleep"
  ],
  [
    "vase used to hold flower offerings (often made of gilded copper)",
    "roller coaster"
  ],
  [
    "pyramid",
    "Sahara Desert"
  ],
  [
    "tennis",
    "golf"
  ],
  [
    "newspaper",
    "leaflet"
  ],
  [
    "pedestrian bridge",
    "road"
  ],
  [
    "light bulb",
    "intercom"
  ],
  [
    "rucksack",
    "tote bag"
  ],
  [
    "traditional square chair with armrests and a torii-shaped back (used by the emperor, etc. during ceremonies)",
    "table"
  ],
  [
    "forest",
    "the grass"
  ],
  [
    "detergent",
    "soap"
  ],
  [
    "jar or vase with a long narrow neck",
    "vase used to hold flower offerings (often made of gilded copper)"
  ],
  [
    "mosquito coil",
    "incense"
  ],
  [
    "stairs",
    "emergency exit"
  ],
  [
    "tank (military vehicle)",
    "fire engine"
  ],
  [
    "sports car",
    "family car"
  ],
  [
    "babysitting",
    "fortune slip (usu. bought at a shrine)"
  ],
  [
    "kindergarten",
    "zoo"
  ],
  [
    "aquarium",
    "botanical garden"
  ],
  [
    "library",
    "aquarium"
  ],
  [
    "lateness",
    "sleeping in late"
  ],
  [
    "lie",
    "natural airhead"
  ],
  [
    "fat",
    "person who prefers sweet things to alcoholic drinks"
  ],
  [
    "dog (Canis (lupus) familiaris)",
    "hamster"
  ],
  [
    "psychopath",
    "ennui"
  ],
  [
    "tobacco",
    "sauna"
  ],
  [
    "magic marker",
    "mechanical pencil"
  ],
  [
    "paper bag",
    "eye bags"
  ],
  [
    "abacus",
    "protractor"
  ],
  [
    "electric fan",
    "air conditioner"
  ],
  [
    "school festival",
    "music festival"
  ],
  [
    "confession (to a crime, wrongdoing, etc.)",
    "love letter"
  ],
  [
    "affected",
    "(young) man adhering to a masculine version of gyaru fashion (usually marked by hair dyed brown or blond, gaudy clothes and accessories)"
  ],
  [
    "eye contact",
    "to join hands (with)"
  ],
  [
    "memorial day",
    "present"
  ],
  [
    "blond hair",
    "short hair"
  ],
  [
    "disappointed love",
    "marital quarrel"
  ],
  [
    "touching (someone)",
    "body language"
  ],
  [
    "whispering into a person's ear",
    "touching (someone)"
  ],
  [
    "woman or girl who acts cute by playing innocent and helpless",
    "wicked tongue"
  ],
  [
    "dimple",
    "double tooth"
  ],
  [
    "diet",
    "appeal (e.g. for peace)"
  ],
  [
    "nail",
    "manicure"
  ],
  [
    "kanji",
    "cursive style"
  ],
  [
    "row of teeth",
    "naturally curly hair"
  ],
  [
    "devoted husband",
    "avid reader"
  ],
  [
    "dress",
    "miniskirt"
  ],
  [
    "gambler",
    "wasteful person"
  ],
  [
    "engagement ring",
    "bunch of flowers"
  ],
  [
    "scented water used for purification",
    "fabric softener"
  ],
  [
    "sunglasses",
    "hat"
  ],
  [
    "(formal) meeting with a view to marriage",
    "engagement gift"
  ],
  [
    "adultery",
    "pout"
  ],
  [
    "(attractively) small face (esp. a woman's)",
    "double-edged eyelid"
  ],
  [
    "thump-thump",
    "hazy"
  ],
  [
    "sillago (any fish of genus Sillago, esp. the Japanese whiting, Sillago japonica)",
    "hug"
  ],
  [
    "vending machine",
    "public telephone"
  ],
  [
    "(finger) ring",
    "necklace"
  ],
  [
    "sports-minded",
    "cultural"
  ],
  [
    "visual kei",
    "beautiful face"
  ],
  [
    "(formal) meeting with a view to marriage",
    "engagement"
  ],
  [
    "dark circles around the eyes",
    "swelling"
  ],
  [
    "Napoleon",
    "Hitler"
  ],
  [
    "Disneyland",
    "Tokyo Dome"
  ],
  [
    "Kyoto (city, prefecture)",
    "Kamakura (city)"
  ],
  [
    "Kobe (city)",
    "Ginza (Tokyo neighborhood)"
  ],
  [
    "Okinawa (city, prefecture)",
    "Fukuoka (city, prefecture)"
  ],
  [
    "Merlion",
    "Statue of Liberty"
  ],
  [
    "Sapporo (city in Hokkaido)",
    "Hakata (old but still commonly used name for Fukuoka)"
  ],
  [
    "Kobe (city)",
    "Yokohama (city)"
  ],
  [
    "near",
    "udon"
  ],
  [
    "bibimbap (Korean rice dish)",
    "pad krapow (basil and minced meat stir fry served with rice)"
  ],
  [
    "kalbi",
    "skirt steak"
  ],
  [
    "lettuce (Lactuca sativa)",
    "Korean lettuce"
  ],
  [
    "pasta",
    "cooked white rice"
  ],
  [
    "sukiyaki",
    "gyudon"
  ],
  [
    "macaron (meringue-based sandwich cookie)",
    "marshmallow"
  ],
  [
    "shortcake (layered cream and fruit cake; in Japan, made with sponge cake)",
    "pancake"
  ],
  [
    "kusaya",
    "natto (fermented soybeans)"
  ],
  [
    "strawberry (esp. the garden strawberry, Fragaria x ananassa)",
    "cherry tomato"
  ],
  [
    "manjū (steamed bun) with meat filling",
    "xiaolongbao (eastern Chinese steamed bun)"
  ],
  [
    "cold noodles (in Korean style)",
    "chilled Chinese noodles"
  ],
  [
    "soft serve ice cream",
    "shaved ice (usually served with flavored simple syrup)"
  ],
  [
    "forbearance (in the face of difficulty, persecution, etc.)",
    "hormone"
  ],
  [
    "waffle",
    "hotcake"
  ],
  [
    "bok choy (Brassica rapa subsp. chinensis; esp. cultivars with white stalks)",
    "Welsh onion (Allium fistulosum)"
  ],
  [
    "beer",
    "champagne"
  ],
  [
    "ehōmaki",
    "broiled eel served over rice in a lacquered box"
  ],
  [
    "katsudon",
    "udon"
  ],
  [
    "pizza",
    "gratin"
  ],
  [
    "sashimi (raw sliced fish, shellfish or crustaceans)",
    "kamaboko"
  ],
  [
    "matsutake mushroom (Tricholoma matsutake)",
    "deformity"
  ],
  [
    "matsutake mushroom (Tricholoma matsutake)",
    "Chinese soft-shelled turtle (Pelodiscus sinensis)"
  ],
  [
    "matsutake mushroom (Tricholoma matsutake)",
    "bamboo shoot"
  ],
  [
    "kinoko",
    "bamboo shoot"
  ],
  [
    "yakisoba",
    "grilled squid"
  ],
  [
    "coffee",
    "café au lait"
  ],
  [
    "black tea",
    "green tea"
  ],
  [
    "Guam",
    "confection (e.g. candy, mochi)"
  ],
  [
    "rigid frame",
    "pancake"
  ],
  [
    "yogurt",
    "jello"
  ],
  [
    "soft serve ice cream",
    "purine"
  ],
  [
    "waffle",
    "doughnut"
  ],
  [
    "cookie",
    "rice cracker"
  ],
  [
    "ochazuke",
    "gukbap (Korean rice soup)"
  ],
  [
    "boiled egg",
    "sausage"
  ],
  [
    "scrambled eggs",
    "sausage"
  ],
  [
    "umeboshi",
    "nori"
  ],
  [
    "umeboshi",
    "sliced vegetables pickled in soy sauce"
  ],
  [
    "umeboshi",
    "raisin"
  ],
  [
    "raisin",
    "beef jerky"
  ],
  [
    "cherry tomato",
    "cherry fruit (esp. sweet cherry, Prunus avium)"
  ],
  [
    "pancake",
    "tapioca"
  ],
  [
    "basket clam (Corbiculidae spp.)",
    "common orient clam (Meretrix lusoria)"
  ],
  [
    "Japanese scallop (Patinopecten yessoensis)",
    "blood clam (Scapharca broughtonii)"
  ],
  [
    "curry (esp. Japanese curry)",
    "yakisoba"
  ],
  [
    "curry (esp. Japanese curry)",
    "beef stew"
  ],
  [
    "aojiru",
    "tomato juice"
  ],
  [
    "mandarin (esp. the satsuma mandarin (Citrus unshiu))",
    "chopped wood"
  ],
  [
    "Japanese scallop (Patinopecten yessoensis)",
    "abalone"
  ],
  [
    "basket clam (Corbiculidae spp.)",
    "Manila clam (Ruditapes philippinarum)"
  ],
  [
    "curry (esp. Japanese curry)",
    "gratin"
  ],
  [
    "biwa (Japanese lute)",
    "chopped wood"
  ],
  [
    "lever",
    "hormone"
  ],
  [
    "mango (Mangifera indica)",
    "Suica"
  ],
  [
    "rice cakes",
    "swallowing a great amount of tea or medicine"
  ],
  [
    "onigiri",
    "sandwich"
  ],
  [
    "sandwich",
    "panini"
  ],
  [
    "coffee",
    "roasted green tea"
  ],
  [
    "beer",
    "highball"
  ],
  [
    "chopped kabayaki eel on rice",
    "(tip section of) chicken wing"
  ],
  [
    "mango (Mangifera indica)",
    "melon (esp. a muskmelon, Cucumis melo)"
  ],
  [
    "samgyeopsal",
    "bibimbap (Korean rice dish)"
  ],
  [
    "kinako mochi",
    "rice ball coated with sweetened red beans, soybean flour or sesame"
  ],
  [
    "rice ball coated with sweetened red beans, soybean flour or sesame",
    "swallowing a great amount of tea or medicine"
  ],
  [
    "curry (esp. Japanese curry)",
    "nikujaga"
  ],
  [
    "curry (esp. Japanese curry)",
    "stew"
  ],
  [
    "chocolate",
    "Guam"
  ],
  [
    "chocolate",
    "purine"
  ],
  [
    "éclair",
    "purine"
  ],
  [
    "sweet-and-sour pork",
    "stir-fried shrimp in chili sauce"
  ],
  [
    "caviar",
    "foie gras"
  ],
  [
    "lever",
    "Chinese soft-shelled turtle (Pelodiscus sinensis)"
  ],
  [
    "toothbrush",
    "washing one's hands"
  ],
  [
    "boxed lunch bought at a station (often a local specialty)",
    "near"
  ],
  [
    "remedy for a cold",
    "mouthwash"
  ],
  [
    "jellyfish",
    "jello"
  ],
  [
    "Chinese cooking",
    "French food"
  ],
  [
    "durian (fruit)",
    "litchi (Nephelium litchi)"
  ],
  [
    "uniaxial",
    "pomegranate (Punica granatum)"
  ],
  [
    "raisin",
    "uniaxial"
  ],
  [
    "yakiniku",
    "yakitori"
  ],
  [
    "banana",
    "pineapple (Ananas comosus)"
  ],
  [
    "apple",
    "strawberry"
  ],
  [
    "rice topped with raw egg (often seasoned with soy sauce)",
    "ochazuke"
  ],
  [
    "chili oil mixed with chopped garlic, onions, etc.",
    "gim"
  ],
  [
    "green tea",
    "barley tea"
  ],
  [
    "oolong tea",
    "barley tea"
  ],
  [
    "pear (esp. Japanese pear)",
    "inhuman"
  ],
  [
    "peach (Prunus persica)",
    "strawberry (esp. the garden strawberry, Fragaria x ananassa)"
  ],
  [
    "coriander (Coriandrum sativum)",
    "bell pepper"
  ],
  [
    "bell pepper",
    "removal of dissolute sons from the family register (Edo period)"
  ],
  [
    "bell pepper (esp. red and yellow)",
    "lemon"
  ],
  [
    "okonomiyaki",
    "pizza"
  ],
  [
    "gentle spring rain",
    "Chinese-style stir-fry containing green peppers and meat"
  ],
  [
    "natto (fermented soybeans)",
    "tofu"
  ],
  [
    "macaroni",
    "gnocchi"
  ],
  [
    "gyudon",
    "dried ginger root (trad. medicine)"
  ],
  [
    "throat lozenge",
    "mint"
  ],
  [
    "soy sauce",
    "sesame oil"
  ],
  [
    "black soybean",
    "buckwheat flour"
  ],
  [
    "mapo tofu (spicy Sichuan dish of tofu and minced meat)",
    "gyoza"
  ],
  [
    "universe",
    "uninhabited island"
  ],
  [
    "police",
    "lawyer"
  ],
  [
    "abacus",
    "electronic massager"
  ],
  [
    "boneless rib (esp. of pork or beef)",
    "sunflower (Helianthus annuus)"
  ],
  [
    "rhinoceros beetle (esp. the Japanese rhinoceros beetle, Trypoxylus dichotomus)",
    "pillbug"
  ],
  [
    "swallow (bird of the Hirundinidae family)",
    "pigeon"
  ],
  [
    "elephant (Elephantidae spp.)",
    "giraffe (Giraffa camelopardalis)"
  ],
  [
    "pasta",
    "gratin"
  ],
  [
    "taxi",
    "bass (fish, e.g. Japanese seabass)"
  ],
  [
    "hot spring",
    "footbath"
  ],
  [
    "suit (clothing)",
    "(formal) shirt"
  ],
  [
    "English (language)",
    "Kansai dialect"
  ],
  [
    "hoe-shaped helmet crest",
    "praying mantis (esp. the narrow-winged mantis, Tenodera angustipennis)"
  ],
  [
    "jellyfish",
    "cuttlefish"
  ],
  [
    "octopus",
    "prawn"
  ],
  [
    "salted salmon roe",
    "preserved food boiled in soy"
  ],
  [
    "movie",
    "stage (of a theatre, concert hall, etc.)"
  ],
  [
    "one-liner",
    "magic (illusion)"
  ],
  [
    "dice",
    "roulette"
  ],
  [
    "volcano",
    "sea of trees"
  ],
  [
    "merry-go-round",
    "Ferris wheel"
  ],
  [
    "change of occupation",
    "searching for a marriage partner"
  ],
  [
    "water well",
    "public telephone"
  ],
  [
    "belt (waist, seat, etc.)",
    "wristwatch"
  ],
  [
    "utility pole",
    "guardrail"
  ],
  [
    "ginger ale",
    "lemonade"
  ],
  [
    "handrail",
    "strap (to hang onto)"
  ],
  [
    "piano",
    "penmanship"
  ],
  [
    "timetable",
    "transfer information (e.g. changing trains)"
  ],
  [
    "Olympics",
    "election"
  ],
  [
    "lateness",
    "feigned illness"
  ],
  [
    "bad",
    "leader of the pack (of a group of kids)"
  ],
  [
    "gem",
    "fossil"
  ],
  [
    "salesman",
    "engineer"
  ],
  [
    "scented water used for purification",
    "water offered to wrestlers just prior to a bout"
  ],
  [
    "drinking straw",
    "(table) napkin"
  ],
  [
    "aurora",
    "rainbow"
  ],
  [
    "rainbow",
    "thunder"
  ],
  [
    "kindergarten",
    "nursery school"
  ],
  [
    "lightning strike",
    "earthquake"
  ],
  [
    "birthday",
    "New Year's Day"
  ],
  [
    "contact lens",
    "wristwatch"
  ],
  [
    "museum",
    "zoo"
  ],
  [
    "baby",
    "hamster"
  ],
  [
    "New Year's gift (usu. money given to a child by relatives and visitors)",
    "personal expenses"
  ],
  [
    "siblings",
    "cousin (younger female)"
  ],
  [
    "sake (rice wine)",
    "Japanese history"
  ],
  [
    "sake (rice wine)",
    "wine"
  ],
  [
    "(afternoon) nap",
    "dozing off in the middle of doing something (esp. in an online chat or during an online game)"
  ],
  [
    "champagne",
    "wine"
  ],
  [
    "pedometer",
    "stopwatch"
  ],
  [
    "sundial",
    "cuckoo clock"
  ],
  [
    "(thick) scarf",
    "(chemical) body warmer"
  ],
  [
    "(room) heater",
    "scarf (esp. a lightweight summer scarf worn by women)"
  ],
  [
    "blanket",
    "futon"
  ],
  [
    "(chemical) body warmer",
    "hot-water bottle"
  ],
  [
    "fear",
    "loyalty"
  ],
  [
    "(non-documentary) television series",
    "news"
  ],
  [
    "hourglass",
    "alarm clock"
  ],
  [
    "timer",
    "stopwatch"
  ],
  [
    "NEET (young person not in education, employment or training)",
    "albite"
  ],
  [
    "cook",
    "patissier"
  ],
  [
    "window",
    "entrance"
  ],
  [
    "astomatous",
    "weird"
  ],
  [
    "(one's) superior",
    "cruel wife"
  ],
  [
    "garbage can",
    "(corrugated) cardboard"
  ],
  [
    "virtuous mind",
    "(coming to an) agreement"
  ],
  [
    "ramune",
    "chocolate"
  ],
  [
    "dressing",
    "soy sauce"
  ],
  [
    "debt",
    "leaving a restaurant without paying"
  ],
  [
    "cartoon",
    "journal"
  ],
  [
    "iron (for pressing clothes)",
    "(aircraft) hangar"
  ],
  [
    "shelf",
    "door (Western-style, car, etc.)"
  ],
  [
    "entrance",
    "living"
  ],
  [
    "real estate agent",
    "removalist"
  ],
  [
    "(true) Tokyoite",
    "hick"
  ],
  [
    "salmon (Salmonidae spp.)",
    "deep-fried food (esp. chicken)"
  ],
  [
    "popcorn",
    "potato chips"
  ],
  [
    "insight",
    "fortitude"
  ],
  [
    "public bath",
    "(public) park"
  ],
  [
    "cutter",
    "knife"
  ],
  [
    "khan (medieval ruler of a Tatary tribe)",
    "tear"
  ],
  [
    "winter vacation",
    "summer vacation"
  ],
  [
    "albite",
    "side job"
  ],
  [
    "contact lens",
    "glasses"
  ],
  [
    "cellophane tape",
    "packing tape"
  ],
  [
    "near",
    "surface of a wound"
  ],
  [
    "ice hockey",
    "curling"
  ],
  [
    "merry-go-round",
    "roller coaster"
  ],
  [
    "term deposit",
    "equity investment"
  ],
  [
    "Wednesday",
    "carbonated water"
  ],
  [
    "mustard",
    "jalapeno pepper"
  ],
  [
    "cat café",
    "maid cafe"
  ],
  [
    "cactus",
    "aloe (esp. arborescens)"
  ],
  [
    "manzai",
    "singing together"
  ],
  [
    "shallow tray (usu. steel or plastic)",
    "racket"
  ],
  [
    "first shrine visit of the New Year",
    "first sunrise of the year"
  ],
  [
    "sea otter (Enhydra lutris)",
    "true seal (animal)"
  ],
  [
    "tortoise",
    "anaconda (esp. the green anaconda, Eunectes murinus)"
  ],
  [
    "mug",
    "tumble dryer"
  ],
  [
    "emergency exit",
    "fire extinguisher"
  ],
  [
    "vaulting horse",
    "skipping rope"
  ],
  [
    "hole in one",
    "home run"
  ],
  [
    "limousine (stretched car)",
    "cruiser (i.e. warship or cabin cruiser)"
  ],
  [
    "centipede",
    "cockroach"
  ],
  [
    "low dining table",
    "folding paper-case"
  ],
  [
    "lawn",
    "water fountain"
  ],
  [
    "(police) detective",
    "detective"
  ],
  [
    "chess",
    "go (board game)"
  ],
  [
    "salt and pepper",
    "blend of seven spices (cayenne, sesame, Japanese pepper, citrus peel, etc.)"
  ],
  [
    "time machine",
    "anywhere door"
  ],
  [
    "urban legend",
    "gossip"
  ],
  [
    "fire extinguisher",
    "emergency staircase"
  ],
  [
    "shredder",
    "treasure house"
  ],
  [
    "metronome",
    "timer"
  ],
  [
    "dozing off in the middle of doing something (esp. in an online chat or during an online game)",
    "lapse of memory"
  ],
  [
    "aroma oil",
    "aroma candle"
  ],
  [
    "tequila",
    "vodka"
  ],
  [
    "hairy caterpillar",
    "centipede"
  ],
  [
    "split end of hair",
    "kinky hair"
  ],
  [
    "invisible person (in science fiction, etc.)",
    "magician"
  ],
  [
    "baby bottle",
    "stroller"
  ],
  [
    "hole in one",
    "grand slam"
  ],
  [
    "pimple",
    "white hair"
  ],
  [
    "peeler (for peeling a label from its base in a barcode printer)",
    "mixer"
  ],
  [
    "writing paper",
    "man of ability"
  ],
  [
    "cone",
    "tuna (esp. canned)"
  ],
  [
    "avocado (Persea americana)",
    "removal of dissolute sons from the family register (Edo period)"
  ],
  [
    "sukiyaki",
    "chankonabe"
  ],
  [
    "snowman",
    "Kamakura (city)"
  ],
  [
    "washing one's hands",
    "gargling"
  ],
  [
    "last-minute cancellation",
    "reading but not responding to a text message (in a chat application)"
  ],
  [
    "tree sparrow (Passer montanus)",
    "pigeon"
  ],
  [
    "English proficiency test (esp. the STEP test)",
    "test of kanji skills"
  ],
  [
    "crab",
    "prawn"
  ],
  [
    "crab",
    "deformity"
  ],
  [
    "ocean sunfish (Mola mola)",
    "whale (Cetacea spp.)"
  ],
  [
    "dryer (esp. hair)",
    "drying machine"
  ],
  [
    "hypnotism",
    "fraud"
  ],
  [
    "roll of banknotes",
    "gold nugget"
  ],
  [
    "Palace of the Dragon King",
    "Onigashima"
  ],
  [
    "mouse",
    "cat (esp. the domestic cat, Felis catus)"
  ],
  [
    "chopped wood",
    "pear (esp. Japanese pear)"
  ],
  [
    "Vienna sausage",
    "bacon"
  ],
  [
    "croquette",
    "curry (esp. Japanese curry)"
  ],
  [
    "owl (esp. the Ural owl, Strix uralensis)",
    "Aum Shinrikyo"
  ],
  [
    "kotatsu",
    "(room) heater"
  ],
  [
    "birthday",
    "Christmas"
  ],
  [
    "manjū (steamed bun) with meat filling",
    "oden"
  ],
  [
    "graduation ceremony",
    "school entrance ceremony"
  ],
  [
    "water offered to wrestlers just prior to a bout",
    "latex (milky fluid found in plants)"
  ],
  [
    "mustard",
    "chili sauce"
  ],
  [
    "soy sauce ramen",
    "tonkotsu ramen"
  ],
  [
    "alcohol-based (hand) sanitizer",
    "hand soap"
  ],
  [
    "rental car",
    "taxi"
  ],
  [
    "rental car",
    "tourist bus"
  ],
  [
    "rushing to get on the train (bus, etc.) before the door closes",
    "texting while walking"
  ],
  [
    "stroller",
    "three wheeled vehicle (tricycle, motorcycle, etc.)"
  ],
  [
    "yakisoba",
    "Chinese-style fried rice"
  ],
  [
    "hallway slippers",
    "slipper"
  ],
  [
    "jungle gym",
    "swing"
  ],
  [
    "exorcism rite",
    "prayer"
  ],
  [
    "fireball",
    "fairy"
  ],
  [
    "massage",
    "stretch"
  ],
  [
    "staying up late",
    "drinking and eating too much"
  ],
  [
    "suit (clothing)",
    "bow tie"
  ],
  [
    "zabuton",
    "folding paper-case"
  ],
  [
    "black rotary-dial telephone",
    "telephone made from two cans and a piece of string"
  ],
  [
    "perm (hairstyle)",
    "hair dyeing"
  ],
  [
    "Santa Claus",
    "reindeer (Rangifer tarandus)"
  ],
  [
    "pipe-organ",
    "grand piano"
  ],
  [
    "digger",
    "(mobile) crane"
  ],
  [
    "Chinese-style hot pot",
    "kimchi hot pot"
  ],
  [
    "peanut (Arachis hypogaea)",
    "edamame (green soybeans)"
  ],
  [
    "balloon (esp. small, toy variety)",
    "soap bubble"
  ],
  [
    "spiny lobster (esp. Japanese spiny lobster, Panulirus japonicus)",
    "hair crab (Erimacrus isenbeckii)"
  ],
  [
    "rice seasoning (usu. containing fish meal, seaweed, sesame, etc.)",
    "seasoned nori (laver)"
  ],
  [
    "colored pencil",
    "crayon"
  ],
  [
    "hiccup",
    "wind"
  ],
  [
    "planetarium",
    "movie theatre"
  ],
  [
    "first sunrise of the year",
    "first dream of the year"
  ],
  [
    "wasabi (Wasabia japonica)",
    "blend of seven spices (cayenne, sesame, Japanese pepper, citrus peel, etc.)"
  ],
  [
    "umeboshi",
    "pickles"
  ],
  [
    "umeboshi",
    "tomato (Solanum lycopersicum)"
  ],
  [
    "mixed vegetable and seafood tempura",
    "croquette"
  ],
  [
    "guitar",
    "ukulele"
  ],
  [
    "baby bottle",
    "teething ring"
  ],
  [
    "spam",
    "crank call"
  ],
  [
    "macaroni salad",
    "potato salad"
  ],
  [
    "album",
    "diary"
  ],
  [
    "Eiffel Tower",
    "Merlion"
  ],
  [
    "ding-dong dash",
    "crank call"
  ],
  [
    "scorpion (Scorpiones spp.)",
    "tarantula (common name for large spiders)"
  ],
  [
    "closet",
    "shoe box"
  ],
  [
    "calculator (electronic)",
    "stopwatch"
  ],
  [
    "First love",
    "First relationship",
    "First date",
    "First kiss",
    "Holding hands",
    "First confession"
  ],
  [
    "Date",
    "Hug",
    "Kiss",
    "Holding hands",
    "Confession"
  ],
  [
    "One-way love",
    "Long-distance relationship",
    "Heart broken",
    "Love triangle relationship with his/her friends",
    "A conflicting triangle relationship you want to win",
    "Being engaged while having another boyfriend/girlfriend",
    "Having several boyfriends/girlfriends",
    "Not finding \"the one\""
  ],
  [
    "Someone with good hygiene",
    "Someone with good fashion sense",
    "Someone serious",
    "Someone rich",
    "Someone smart",
    "Someone very thoughful",
    "Someone very supportive",
    "Someone who is good at anything",
    "Someone careless",
    "Someone arrogant"
  ],
  [
    "Mask",
    "Sunglasses",
    "Glasses",
    "Suit",
    "Hat",
    "Blue jeans"
  ],
  [
    "Coffee",
    "Lemon tea",
    "Milk tea",
    "Green tea",
    "Oolong tea",
    "Cocoa"
  ],
  [
    "Wine",
    "Beer",
    "Japanese sake",
    "Whisky",
    "Plum sake",
    "Coffee"
  ],
  [
    "Apple",
    "Orange",
    "Peach",
    "Pear",
    "Grape",
    "Watermelon",
    "Melon",
    "Tomato",
    "Plum"
  ],
  [
    "Chinese cabbage",
    "Cabbage",
    "Lettuce",
    "Spinach",
    "Onion",
    "Green pepper"
  ],
  [
    "Curry",
    "Beef stew",
    "Ramen",
    "Noodles",
    "Spaghetti",
    "Ravioli"
  ],
  [
    "high-speed train",
    "Local train",
    "Bus",
    "Taxi",
    "Car",
    "Bicycle"
  ],
  [
    "Ambulance",
    "Fire truck",
    "Police car",
    "Tow truck",
    "Hearse"
  ],
  [
    "Tyrannosaurus",
    "Mammoth",
    "Triceratops",
    "Pteranodon",
    "Brachiosaurus",
    "Mosasaurus",
    "Spinosaurus"
  ],
  [
    "Mammoth",
    "Elephant",
    "Hippopotamus",
    "Rhinoceros",
    "Horse"
  ],
  [
    "Wolf",
    "Dog",
    "Fox",
    "Wild dog",
    "Mouse",
    "Rabbit"
  ],
  [
    "Pigeon",
    "Sparrow",
    "Crow",
    "Owl",
    "Swallow",
    "Falcon"
  ],
  [
    "Cat",
    "Wild cat",
    "Tiger",
    "Lion",
    "Jaguar",
    "Panther",
    "Cheetah",
    "Puma"
  ],
  [
    "Dolphin",
    "Whale",
    "Killer whale",
    "Manta ray",
    "Sunfish"
  ],
  [
    "Lizard",
    "Iguana",
    "Turtle",
    "Crocodile",
    "Frog"
  ],
  [
    "Rhinoceros beetle",
    "Stag beetle",
    "Longicorn beetle",
    "Longhorn beetle",
    "Ladybug",
    "Snail"
  ],
  [
    "Cicada",
    "Cricket",
    "Bell cricket",
    "Grasshopper",
    "Mantis"
  ],
  [
    "Bee",
    "Fly",
    "Mosquito",
    "Flying ant",
    "Dragonfly"
  ],
  [
    "Buffalo",
    "Cow",
    "Horse",
    "Deer",
    "Boar",
    "Pork",
    "Sheep",
    "Bear",
    "Rabbit"
  ],
  [
    "Rose",
    "Tulip",
    "Morning glory",
    "Sunflower",
    "Pansy",
    "Margaret",
    "Sweet pea",
    "Lily",
    "Hydrangea",
    "Cosmos"
  ],
  [
    "Typhoon",
    "Thunder",
    "Tornade",
    "Windstorm",
    "Rainbow",
    "Aurora"
  ],
  [
    "River",
    "Waterfall",
    "Sea",
    "Mountain",
    "Valley",
    "Hill",
    "Lake"
  ],
  [
    "Group leader",
    "School kitchen staff",
    "Student council"
  ],
  [
    "Hiking excursion",
    "Field trip",
    "Factory tour",
    "Sports day",
    "School festival",
    "School excursion",
    "Swimming class",
    "Ski class"
  ],
  [
    "Class observation by parents",
    "Parent and child meeting",
    "Academic counseling",
    "Mock exam",
    "Class meeting"
  ],
  [
    "Pencil",
    "Highlighter pen",
    "Multi color pen",
    "mechanical pencil",
    "Ballpoint pen",
    "Red pen",
    "Brush"
  ],
  [
    "First coffee",
    "First soda",
    "First liquor",
    "First beer",
    "First French wine",
    "First breast milk",
    "First Japanese sake"
  ],
  [
    "First thunder",
    "First snow",
    "First typhoon",
    "First rain",
    "First earthquake",
    "First full moon",
    "First lunar eclipse",
    "First solar eclipse",
    "First hail storm",
    "First flowering cherry trees",
    "First heat wave"
  ],
  [
    "First spicy curry taste",
    "First mustard taste",
    "First wasabi taste",
    "First ginger taste",
    "First lemon taste",
    "First red cayenne pepper"
  ],
  [
    "Sexual appetite",
    "Appetite",
    "Wanting to sleep",
    "Wanting to pee",
    "Wanting to poo",
    "Thirst"
  ],
  [
    "School gym clothes",
    "School uniform",
    "Leotard",
    "Swim suit",
    "Lab coat",
    "Suit"
  ],
  [
    "Hiccup",
    "Cough",
    "Sneeze",
    "Runny nose",
    "Burp",
    "Yawn",
    "Tinnitus"
  ],
  [
    "Chocolate eclairs",
    "Cream puffs",
    "Cream-stuffed pastries",
    "Ice cream"
  ],
  [
    "Permanent makeup",
    "Permanent hair removal",
    "Curly hair permanent",
    "Diet",
    "Hair coloring",
    "Straight hair permanent"
  ],
  [
    "Confessing your love by e-mail",
    "Confessing your love on the phone",
    "Confessing your love through an instant messaging app",
    "Confessing your love at a cafe",
    "Confessing your love at the beach",
    "Confessing your love at the movie theater",
    "Confessing your love at the restaurant"
  ],
  [
    "Festival",
    "Barbecue",
    "Fireworks"
  ],
  [
    "Parent-teacher communication notebook",
    "Diary",
    "Letter",
    "Cheat sheet",
    "Class pet journal"
  ],
  [
    "Office romance",
    "teacher student romance",
    "Doctor patient romance",
    "Boss employee romance",
    "Brother sister romance",
    "Romance between cousins",
    "Romance between a prince/princess and a commoner"
  ],
  [
    "Body soap",
    "Soap bar",
    "Dish detergent",
    "Laundry detergent",
    "Shampoo",
    "Rinse",
    "Conditioner"
  ],
  [
    "Grilled meat",
    "Slow cooked meat",
    "Kebab",
    "Hamburg",
    "Steak"
  ],
  [
    "Carrot",
    "Radish",
    "Lotus root",
    "Turnip",
    "Burdock root"
  ],
  [
    "Blood test",
    "Urine test",
    "Stool test",
    "Tuberculosis screening",
    "X-rays"
  ],
  [
    "Abandoned cat",
    "Abandoned dog",
    "Heartbroken best friend",
    "A best friend who failed an entrance exam"
  ],
  [
    "Aroma therapy oil",
    "Aromatic candle",
    "Air freshener",
    "Air fragrance",
    "Perfume",
    "Incense stick",
    "Mosquito repellent",
    "Bug spray"
  ],
  [
    "Sunscreen",
    "Toner",
    "Moisturizing cream",
    "Lip cream",
    "Face soap",
    "Foundation"
  ],
  [
    "Face powder",
    "Lipstick",
    "Eye shadow",
    "Powder blush",
    "Mascara",
    "Fake eyelashes"
  ],
  [
    "Someone careless",
    "Someone arrogant",
    "Someone with restless legs syndrome",
    "Someone unhygienic",
    "Someone insane",
    "Someone weird",
    "Someone stingy",
    "Someone short tempered",
    "An attention whore person",
    "Someone too naive"
  ],
  [
    "Demon",
    "Ghost",
    "Ogre",
    "Goblin",
    "God"
  ],
  [
    "Space",
    "Sky",
    "Heaven",
    "Roof"
  ],
  [
    "Love",
    "Friendship",
    "Trust",
    "Effort",
    "Jealousy"
  ],
  [
    "Light",
    "Sound",
    "Heat",
    "Ultraviolet rays",
    "Electromagnetic waves",
    "Air"
  ],
  [
    "Shooting star",
    "Sun",
    "Space",
    "Satellite",
    "Cloud"
  ],
  [
    "Hourglass",
    "Wristwatch",
    "Stopwatch",
    "Pendulum clock",
    "Wall clock"
  ],
  [
    "Angel",
    "Godness",
    "Elf",
    "Holy Mother",
    "Gremlin"
  ],
  [
    "Sky",
    "Heaven",
    "Reincarnation",
    "Post-mortem",
    "Previous life",
    "Hell"
  ],
  [
    "Hot (weather)",
    "Thickness",
    "Hot (thing, person)",
    "Weight"
  ],
  [
    "Curiosity",
    "Mischief",
    "Phobia",
    "Politeness",
    "Kindness"
  ],
  [
    "Battlefield",
    "Hell",
    "Prison",
    "Abandoned mine"
  ],
  [
    "Gold",
    "Silver",
    "Precious stone",
    "Money",
    "Ring (for fingers)",
    "Picture"
  ],
  [
    "Jealousy",
    "admiration (towards...)",
    "Crush",
    "Love at first sight",
    "Paternal/maternal love"
  ],
  [
    "Oil",
    "Water",
    "Soy sauce",
    "Vinegar",
    "Chicken stock",
    "Cooking alcohol"
  ],
  [
    "Dinosaur",
    "Beast",
    "Wolf",
    "Werewolf"
  ],
  [
    "Bully",
    "Quarrel",
    "Prank",
    "Dictatorship"
  ],
  [
    "Trap",
    "Grave",
    "Root cellar",
    "Cave",
    "Warehouse"
  ],
  [
    "Hotspring",
    "Fountain",
    "Geyser",
    "Waterfall"
  ],
  [
    "Fire",
    "Flame",
    "Magma",
    "Lava",
    "Volcanic ash"
  ],
  [
    "Cell (biology)",
    "Atom",
    "Molecule",
    "Microorganism"
  ],
  [
    "To read",
    "To study",
    "To learn by heart",
    "To listen carefully",
    "Classroom chatter"
  ],
  [
    "Mirror",
    "Glass",
    "Pocket mirror",
    "Floor mirror",
    "Mirror sticker"
  ],
  [
    "Basement",
    "Tunnel",
    "Catacombs",
    "Ditch (infrastructure)"
  ],
  [
    "Vampire",
    "Werewolf",
    "Undead",
    "Zombie"
  ],
  [
    "Gambling",
    "Stock price",
    "Casino"
  ],
  [
    "Medicine",
    "Aspirin",
    "Laxative",
    "Nasal spray",
    "Eye drops",
    "Alcohol"
  ],
  [
    "Footbridge",
    "Escalator",
    "Elevator",
    "Roller coaster"
  ],
  [
    "Anime cosplay",
    "Animal costume",
    "Costume"
  ],
  [
    "Soup",
    "Smoothie",
    "Pot-au-feu (French dish)",
    "Pho (Vietnamese dish)"
  ],
  [
    "Colored contact lenses",
    "Sunglasses",
    "Corrective contact lenses",
    "Glasses"
  ],
  [
    "Wheelbarrow",
    "Electric bicycle",
    "Mini truck",
    "Shopping cart/trolley"
  ],
  [
    "Coin flipping",
    "Rock-paper-scissors",
    "Dice"
  ],
  [
    "Hairpin",
    "Rubber band",
    "Hair band",
    "Scrunchie (for hair)",
    "Hair clip"
  ],
  [
    "Clown",
    "Magician",
    "Juggler",
    "Fire breathing"
  ],
  [
    "Present",
    "Bento (Japanese lunch box)",
    "Gift box",
    "Individually wrapped snacks"
  ],
  [
    "Helicopter",
    "Jet aircraft",
    "Airplane",
    "Hot air balloon",
    "UFO",
    "Drone",
    "Spaceship",
    "Orbiter"
  ],
  [
    "Cityhall",
    "Post office",
    "Convenience store",
    "Supermarket",
    "Drugstore"
  ],
  [
    "Yacht",
    "Sailing ship",
    "Kayak",
    "Cruise ship"
  ],
  [
    "Amateur",
    "Minor (under 18)",
    "Brat",
    "Immature girl",
    "Immature boy"
  ],
  [
    "\"No drinking\"",
    "\"No smoking\"",
    "\"No swimming\"",
    "\"No fishing\"",
    "\"No shoes inside\""
  ],
  [
    "Bookmark",
    "Family photo album",
    "Book cover",
    "Bookbinding"
  ]
];

