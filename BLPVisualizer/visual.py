#global array storing subjects
subjects = []

#global array storing objects 
objects = []


class subjects:
    #initializes new subject
    def __init__(self, name, maximum, starting):
        self.name = name    
        self.maximum = maximum  
        self.starting = starting

    #Adds a new subject to the system. A subject cannot be added if 
    #their starting level is higher than their maximum clearance.
    def add_subject(subj):
        global subjects
        if (self.starting <= self.naximum)
            subjects.append(subj)



class objects: 
    #initializes new object
    def __init__(self, filename, level)
        self.filename = filename
        self.level = level

    #Adds a new object to the system with a designated security
    #classification.
    def add_object(obj)
        global objects
        subjects.append(obj)



#Checks if a subject's current security level exactly matches an
#object's security level. Returns true if they match, and false otherwise.
def validate_levels()

#Allows a subject to change their current operating level.
#   -Constraint: A subject cannot lower their level below their current operating
#       level, nor can they raise it above their maximum clearance.
def set_level()

#Evaluates a read request
#   -Constraint: Must enforce the Simple Security Property.
#   -Dynamic Leveling: If the object's level is higher than the subject's current
#       level, but less than or equal to their maximum clearance, the subject's
#       current level should be automatically raised to match the object's level to
#       allow the read.
def read()

#Evaluates a write request.
#   -Constraint: Must enforce the No Write Down property.
def write() 
