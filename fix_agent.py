import re

with open("run_agent.py", "r") as f:
    content = f.read()

old = '''        response = client.inference.get_chat_completions(
            model="gpt-4o",
            messages=[
                {"role": "system", "content": "You are GhostWatch, an expert AI security analyst."},
                {"role": "user", "content": summary}
            ]
        )
        print("\\n🤖 GhostWatch AI Analysis:")
        print(response.choices[0].message.content)'''

new = '''        openai_client = client.get_openai_client(api_version="2024-06-01")
        response = openai_client.chat.completions.create(
            model="gpt-4o",
            messages=[
                {"role": "system", "content": "You are GhostWatch, an expert AI security analyst."},
                {"role": "user", "content": summary}
            ]
        )
        print("\\n🤖 GhostWatch AI Analysis:")
        print(response.choices[0].message.content)'''

content = content.replace(old, new)
with open("run_agent.py", "w") as f:
    f.write(content)
print("Done")
