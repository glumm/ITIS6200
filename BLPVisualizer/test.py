from visual import * 

def setup():
    global subjects, objects
    subjects.clear()
    objects.clear()
    add_subject("Alice", "S", "U")
    add_subject("Bob",   "C", "C")
    add_subject("Eve",   "U", "U")
    add_object("pub.txt",      "U")
    add_object("emails.txt",   "C")
    add_object("username.txt", "S")
    add_object("password.txt", "TS")

def get_subject(name):
    return next(s for s in subjects if s.name == name)

def get_object(filename):
    return next(o for o in objects if o.filename == filename)


########################################
#            Test Cases                #      
########################################

def case1():
    print("\n============== Case 1 ==============")
    print("[ACTION] >> Alice reads emails.txt")
    setup()
    read(get_subject("Alice"), get_object("emails.txt"))
    disp_state()

def case2():
    print("\n============== Case 2 ==============")
    print("[ACTION] >> Alice reads password.txt")
    setup()
    read(get_subject("Alice"), get_object("password.txt"))
    disp_state()

def case3():
    print("\n============== Case 3 ==============")
    print("[ACTION] >> Eve reads pub.txt")
    setup()
    read(get_subject("Eve"), get_object("pub.txt"))
    disp_state()

def case4():
    print("\n============== Case 4 ==============")
    print("[ACTION] >> Eve reads emails.txt")
    setup()
    read(get_subject("Eve"), get_object("emails.txt"))
    disp_state()

def case5():
    print("\n============== Case 5 ==============")
    print("[ACTION] >> Bob reads password.txt")
    setup()
    read(get_subject("Bob"), get_object("password.txt"))
    disp_state()

def case6():
    print("\n============== Case 6 ==============")
    print("[ACTION] >> Alice reads emails.txt, then writes to pub.txt")
    setup()
    read(get_subject("Alice"), get_object("emails.txt"))
    write(get_subject("Alice"), get_object("pub.txt"))
    disp_state()

def case7():
    print("\n============== Case 7 ==============")
    print("[ACTION] >> Alice reads emails.txt, then writes to password.txt")
    setup()
    read(get_subject("Alice"), get_object("emails.txt"))
    write(get_subject("Alice"), get_object("password.txt"))
    disp_state()

def case8():
    print("\n============== Case 8 ==============")
    print("[ACTION] >> Alice reads emails.txt, writes to emails.txt,")
    print("         >> then reads username.txt, writes to emails.txt")
    setup()
    read(get_subject("Alice"), get_object("emails.txt"))
    write(get_subject("Alice"), get_object("emails.txt"))
    read(get_subject("Alice"), get_object("username.txt"))
    write(get_subject("Alice"), get_object("emails.txt"))
    disp_state()

def case9():
    print("\n============== Case 9 ==============")
    print("[ACTION] >> Alice reads username.txt, writes to emails.txt,")
    print("         >> then reads password.txt, writes to password.txt")
    setup()
    read(get_subject("Alice"), get_object("username.txt"))
    write(get_subject("Alice"), get_object("emails.txt"))
    read(get_subject("Alice"), get_object("password.txt"))
    write(get_subject("Alice"), get_object("password.txt"))
    disp_state()

def case10():
    print("\n============== Case 10 ==============")
    print("[ACTION] >> Alice reads pub.txt, writes to emails.txt,")
    print("         >> then Bob reads emails.txt")
    setup()
    read(get_subject("Alice"), get_object("pub.txt"))
    write(get_subject("Alice"), get_object("emails.txt"))
    read(get_subject("Bob"), get_object("emails.txt"))
    disp_state()

def case11():
    print("\n============== Case 11 ==============")
    print("[ACTION] >> Alice reads pub.txt, writes to username.txt,")
    print("         >> then Bob reads username.txt")
    setup()
    read(get_subject("Alice"), get_object("pub.txt"))
    write(get_subject("Alice"), get_object("username.txt"))
    read(get_subject("Bob"), get_object("username.txt"))
    disp_state()

def case12():
    print("\n============== Case 12 ==============")
    print("[ACTION] >> Alice reads pub.txt, writes to password.txt,")
    print("         >> then Bob reads password.txt")
    setup()
    read(get_subject("Alice"), get_object("pub.txt"))
    write(get_subject("Alice"), get_object("password.txt"))
    read(get_subject("Bob"), get_object("password.txt"))
    disp_state()

def case13():
    print("\n============== Case 13 ==============")
    print("[ACTION] >> Alice reads pub.txt, writes to emails.txt,")
    print("         >> then Eve reads emails.txt")
    setup()
    read(get_subject("Alice"), get_object("pub.txt"))
    write(get_subject("Alice"), get_object("emails.txt"))
    read(get_subject("Eve"), get_object("emails.txt"))
    disp_state()

def case14():
    print("\n============== Case 14 ==============")
    print("[ACTION] >> Alice reads emails.txt, writes to pub.txt,")
    print("         >> then Eve reads pub.txt")
    setup()
    read(get_subject("Alice"), get_object("emails.txt"))
    write(get_subject("Alice"), get_object("pub.txt"))
    read(get_subject("Eve"), get_object("pub.txt"))
    disp_state()

def case15():
    print("\n============== Case 15 ==============")
    print("[ACTION] >> Alice sets her level to S, then reads username.txt")
    setup()
    set_level(get_subject("Alice"), "S")
    read(get_subject("Alice"), get_object("username.txt"))
    disp_state()

def case16():
    print("\n============== Case 16 ==============")
    print("[ACTION] >> Alice reads emails.txt, sets her level to U,")
    print("         >> writes to pub.txt, then Eve reads pub.txt")
    setup()
    read(get_subject("Alice"), get_object("emails.txt"))
    set_level(get_subject("Alice"), "U")
    write(get_subject("Alice"), get_object("pub.txt"))
    read(get_subject("Eve"), get_object("pub.txt"))
    disp_state()

def case17():
    print("\n============== Case 17 ==============")
    print("[ACTION] >> Alice reads username.txt, sets her level to C,")
    print("         >> writes to emails.txt, then Eve reads emails.txt")
    setup()
    read(get_subject("Alice"), get_object("username.txt"))
    set_level(get_subject("Alice"), "C")
    write(get_subject("Alice"), get_object("emails.txt"))
    read(get_subject("Eve"), get_object("emails.txt"))
    disp_state()

def case18():
    print("\n============== Case 18 ==============")
    print("[ACTION] >> Eve reads pub.txt, then reads emails.txt")
    setup()
    read(get_subject("Eve"), get_object("pub.txt"))
    read(get_subject("Eve"), get_object("emails.txt"))
    disp_state()

cases = {
    1: case1,   2: case2,   3: case3,   4: case4,   5: case5,
    6: case6,   7: case7,   8: case8,   9: case9,   10: case10,
    11: case11, 12: case12, 13: case13, 14: case14, 15: case15,
    16: case16, 17: case17, 18: case18
}

def run_menu():
    while True:
        print("\n===== BLP Model Test Harness =====")
        print("Options: \n Specific Case: Enter a case number (1-18) \n [A] Run all test cases \n [Q] Quit")
        choice = input("Choice: ").strip().lower()

        if choice == "q":
            print("Exiting.")
            break
        elif choice == "a":
            for i in range(1, 19):
                cases[i]()
        elif choice.isdigit() and int(choice) in cases:
            cases[int(choice)]()
        else:
            print("Invalid input. Please enter a number 1-18, 'A', or 'Q'.")

if __name__ == "__main__":
    run_menu()
