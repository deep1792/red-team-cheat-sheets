Misconfigured AI on steroids- leaking secrets from Github Private repos & CI/CD configured pipelines

Accidently discovered something interesting and dangerous while performing some interactions with my integrated AI engines with Dev[Sec]Ops pipelines. hence, thought of sharing the real use-case with public and private repos like:

 An #attacker can leverage the #Indirect #Prompt #injection from the integrated #AI engine model in your Dev[Sec]Ops pipelines if misconfigured or with inappropriate access controls or rights.  

In the video, we will cover the Real examples — like GitHub bots leaking data from private repos like a real-attacker using AI prompt a.k.a #prompt #injection and will also help the bounty hunters.

1. What is Prompt Injection?
Prompt Injection is a security vulnerability in AI language models where an attacker manipulates the input prompt to influence or hijack the model’s output, often to bypass restrictions, leak sensitive info, or execute unintended commands.

Think of it as an attacker sneaking malicious instructions into the conversation or input text to trick the AI into doing something harmful or unintended.

For Demo - 
1. Create the PAT - fine grained token
2. provide access to private and personal repo for demo
3. Store the PAT in .env file
4. Change the repo names to the demo lab - public and private repo
5. Run the python file as - python3 ai_lab.py
   i. once the issue is created.
   ii. run the code again to let the AI bot to look the instructions

Youtube Video Link -- https://youtu.be/B4bH0a7rXp4 
