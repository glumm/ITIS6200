#Mapping security levels to integers for boolean logic
LEVELS = {"U": 0, "C": 1, "S": 2, "TS": 3}

#global array storing subjects
subjects = []

#global array storing objects 
objects = []


class Subject:
    #initializes new subject
    def __init__(self, name, maximum, starting):
        self.name = name    
        self.maximum = maximum  
        self.starting = starting
        self.current_level = starting

class Object: 
    #initializes new object
    def __init__(self, filename, level):
        self.filename = filename
        self.level = level


#Adds a new subject to the system. A subject cannot be added if 
#their starting level is higher than their maximum clearance.
def add_subject(name, maximum, starting):
    if (LEVELS[starting] <= LEVELS[maximum]):
        subjects.append(Subject(name, maximum, starting))
    else:
        print(f"ERROR: {name}'s starting clearence exceeds their maximum clearence")

#Adds a new object to the system with a designated security
#classification.
def add_object(filename, level):
    objects.append(Object(filename, level))

#Checks if a subject's current security level exactly matches an
#object's security level. Returns true if they match, and false otherwise.
def validate_levels(subj, obj):
    return LEVELS[subj.current_level] == LEVELS[obj.level]

#Allows a subject to change their current operating level.
#   -Constraint: A subject cannot lower their level below their current operating
#       level, nor can they raise it above their maximum clearance.
def set_level(subj, new_level):
    if(LEVELS[new_level] < LEVELS[subj.current_level]):
        print(f"[STATUS] >> DENIED: cannot lower {subj.name}'s level from {subj.current_level} to {new_level}")      
    if(LEVELS[new_level] > LEVELS[subj.maximum]):
        print("[STATUS] >> DENIED: cannot raise {subj.name}'s level above maximum of {subj.maximum}")
    else: 
        subj.current_level = new_level
    

#Evaluates a read request
#   -Constraint: Must enforce the Simple Security Property.
#   -Dynamic Leveling: If the object's level is higher than the subject's current
#       level, but less than or equal to their maximum clearance, the subject's
#       current level should be automatically raised to match the object's level to
#       allow the read.
def read(subj, obj):
    if LEVELS[obj.level] <= LEVELS[subj.maximum]:
        if LEVELS[obj.level] > LEVELS[subj.current_level]:
            print(f"[STATUS] >> GRANTED: {subj.name} reads {obj.filename}")
            print(f"[INFO] >> {subj.name}'s level raised: {subj.current_level} -> {obj.level}")
            subj.current_level = obj.level
        elif LEVELS[obj.level] == LEVELS[subj.current_level]:
            print(f"[STATUS] >> GRANTED: {subj.name} reads {obj.filename}")
        else:
            print(f"[STATUS] >> DENIED: {subj.name} cannot read {obj.filename} (object level too low)")
    else:
        print(f"[STATUS] >> DENIED: {subj.name} cannot read {obj.filename} (exceeds max clearance)")

#Evaluates a write request.
#   -Constraint: Must enforce the No Write Down property.
def write(subj, obj):
    if LEVELS[subj.current_level] <= LEVELS[obj.level]:
        print(f"[STATUS] >> GRANTED: {subj.name} writes to {obj.filename}")
    else:
        print(f"[STATUS] >> DENIED: {subj.name} cannot write to {obj.filename}")

#Displays current state 
def disp_state():
    print("\n--------Current BLP State --------")
    for s in subjects: 
        print(f"[Subject] {s.name}: Curr = {s.current_level}, Max = {s.maximum}")
    for o in objects:
        print(f"[Object] {o.filename}: Level = {o.level}")

