import re
import json

def extract_qa_pairs_to_jsonl(file_path, output_file="formatted_data.jsonl"):
    with open(file_path, 'r', encoding='utf-8') as file:
        content = file.read()

    # Adjusted patterns to match "Q:" "Q." "Q;" "Questioner:" and "M:"
    question_pattern = r"(?:Q[:.;]|Questioner:)(.*?)(?=M:)"  # Matches Q:, Q., Q;, or Questioner:, up to "M:"
    answer_pattern = r"M:(.*?)(?=(?:Q[:.;]|Questioner:)|$)"   # Matches "M:" up to next question marker or end

    # Extract questions and answers
    questions = re.findall(question_pattern, content, re.DOTALL)
    answers = re.findall(answer_pattern, content, re.DOTALL)

    # Remove the last Q&A pair to avoid capturing the appendix
    if questions and answers:
        questions = questions[:-1]
        answers = answers[:-1]

    # Function to clean text by removing unwanted newlines
    def clean_text(text):
        text = re.sub(r'\s+', ' ', text)  # Replace all whitespace sequences with a single space
        return text.strip()

    # Open the output file and write each Q&A pair in JSONL format
    with open(output_file, 'w', encoding='utf-8') as f:
        for question, answer in zip(questions, answers):
            # Clean question and answer text
            question_cleaned = clean_text(question)
            answer_cleaned = clean_text(answer)

            # Format each pair with a system prompt explaining that the LLM is Nisargadatta Maharaj
            formatted_pair = {
                "system": "You are embodying Sri Nisargadatta Maharaj, an Advaita Vedanta teacher known for guiding students in self-inquiry to realize their true nature beyond the mind and body. Answer questions from the perspective of Maharaj, with clarity and insight on non-dualism, detachment, and self-realization.",
                "prompt": f"Student: {question_cleaned}\nAnswer as Maharaj:\n",
                "completion": f"Maharaj: {answer_cleaned}\n"
            }
            f.write(json.dumps(formatted_pair) + "\n")
    
    print(f"Q&A pairs have been formatted and saved to '{output_file}' in JSONL format.")

# Usage
file_path = "I_Am_That.txt"  # Update with your file path
extract_qa_pairs_to_jsonl(file_path)

