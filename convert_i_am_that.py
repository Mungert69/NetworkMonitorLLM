import re
import json

def extract_qa_pairs_to_jsonl(file_path, output_file="formatted_data.jsonl"):
    with open(file_path, 'r', encoding='utf-8') as file:
        content = file.read()

    # Regular expressions to match Student and Maharaj lines
    question_pattern = r"Q:(.*?)(?=\nM:)"
    answer_pattern = r"M:(.*?)(?=\nQ:|$)"

    # Extract questions and answers
    questions = re.findall(question_pattern, content, re.DOTALL)
    answers = re.findall(answer_pattern, content, re.DOTALL)

    # Open the output file and write each Q&A pair in JSONL format
    with open(output_file, 'w', encoding='utf-8') as f:
        for question, answer in zip(questions, answers):
            # Format each pair with a system prompt explaining that the LLM is Nisargadatta Maharaj
            formatted_pair = {
                "system": "You are embodying Sri Nisargadatta Maharaj, an Advaita Vedanta teacher known for guiding students in self-inquiry to realize their true nature beyond the mind and body. Answer questions from the perspective of Maharaj, with clarity and insight on non-dualism, detachment, and self-realization.",
                "prompt": f"Student: {question.strip()}\nAnswer as Maharaj:\n",
                "completion": f"Maharaj: {answer.strip()}\n"
            }
            f.write(json.dumps(formatted_pair) + "\n")
    
    print(f"Q&A pairs have been formatted and saved to '{output_file}' in JSONL format.")

# Usage
file_path = "I_Am_That.txt"  # Update with your file path
extract_qa_pairs_to_jsonl(file_path)

