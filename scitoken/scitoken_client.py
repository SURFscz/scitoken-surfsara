import SciTokenClass


scitokenins = SciTokenClass.SciTokenClass(1)
# The flow is the following:
# 1. You generate a base token with generateBaseSciToken() which
#    will generate a Scitoken after generating a private key
# 2. Then generate a normal token by using the relevant base token.
#    Since the tokens can be chained, the relevant permission hierarchies
#    must be taken into consideration...



token=scitokenins.generateRefreshSciToken()
#token['scp'] = ['write:/home/example'] # Add authorization....
token['scp'] = ['write:/home/example', 'write:/home/testData']
token2 = scitokenins.generateRefreshSciToken(token)  # This token should have all the permissions of the base token.

# Add authorizations... TODO : This is missing, check its status and modify SciToken accordingly...
#token['scp'] = token.claims()
token2.update_claims({'scp': ['read:/home/example']})

#[('write', '/home/testData'), ('read', '/home/example'), ('write', '/home/example')]
'''
val = scitokens.Validator()
print 'Validation result : '
print val.validate(token)
'''

# This already does validation for the defined claim types...
enf = scitokenins.generateEnforcer("local")

print enf.generate_acls(token2)
print enf.test(token, 'write', '/home/example/test_file') #this should work...
print enf.test(token, 'read', '/home/example/test_file')
print enf.test(token, 'write', '/home/other/test_file')
print enf.test(token, 'read', '/home/example/test_file')

#print token.header #token_serialized_bytes
#print token.payload
#token2 = scitokens.SciToken(key=private_key)
#print token2