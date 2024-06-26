class Confidence:
    def __init__(self, severity=0, past_occurrences=0, exploitability=0, impact=0):
        self.severity = severity
        self.past_occurrences = past_occurrences
        self.exploitability = exploitability
        self.impact = impact

    def add_confidence(self, severity=0, past_occurrences=0, exploitability=0, impact=0):
        self.severity += severity
        self.past_occurrences += past_occurrences
        self.exploitability += exploitability
        self.impact += impact

    def calculate_confidence(self):
        score = (self.severity * 0.3) + \
                (self.past_occurrences * 0.3) + \
                (self.exploitability * 0.2) + \
                (self.impact * 0.1)

        if score >= 0.75:
            return "Critical"
        elif score >= 0.5:
            return "High"
        elif score >= 0.25:
            return "Medium"
        else:
            return "Low"
