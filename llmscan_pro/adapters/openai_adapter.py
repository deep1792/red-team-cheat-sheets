import os
class OpenAIAdapter:
    name = 'openai'
    def __init__(self, model='gpt-4o-mini'):
        self.model = model
        if not os.environ.get('OPENAI_API_KEY'):
            raise RuntimeError('OPENAI_API_KEY not set in environment')
    def generate(self, prompt):
        raise NotImplementedError('OpenAIAdapter.generate() must be implemented by the user.')
