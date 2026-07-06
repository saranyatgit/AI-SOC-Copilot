from threat_intelligence.mitre_mapper import get_attack_details

attack = input("Enter attack name: ")

result = get_attack_details(attack)

if result:

    print("\nAttack:", attack)
    print("Tactic:", result["tactic"])
    print("Technique ID:", result["technique_id"])
    print("Description:", result["description"])
    print("Mitigation:", result["mitigation"])

else:

    print("Attack not found.")