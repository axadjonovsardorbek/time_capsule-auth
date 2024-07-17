INSERT INTO users (id, username, email, password_hash, full_name, date_of_birth, privacy_level, notifications_enabled, language, theme)
VALUES 
    ('11111111-1111-1111-1111-111111111111', 'alice', 'alice@example.com', 'cgmS2r77aQ5hUbVFtQrr7JSVbnJkv60R2c/58h7w3Bg=', 'Alice Wonderland', '1990-05-15', 'friends_only', 'off', 'en', 'system'),
    ('22222222-2222-2222-2222-222222222222', 'bob', 'bob@example.com', 'mM2U+kjzF7LyPLFiSeTAZ1JXLvRHylfJc+X0+uqY37E=', 'Bob Builder', '1985-07-20', 'nobody', 'off', 'es', 'dark'),
    ('33333333-3333-3333-3333-333333333333', 'charlie', 'charlie@example.com', 'hR0v8XWaaJ9Gh1CeqfgbX5F++2HpCXnA7Oo+/djWbl8=', 'Charlie Chocolate', '2000-12-25', 'all', 'on', 'fr', 'light');

-- Inserting mock data into memories table
INSERT INTO memories (id, user_id, title, description, date, tags, location, place_name, privacy)
VALUES 
    ('aaaaaaa1-aaaa-aaaa-aaaa-aaaaaaaaaaa1', '11111111-1111-1111-1111-111111111111', 'Summer Vacation', 'Beach party with friends', '2023-06-15', ARRAY['beach', 'party'], POINT(50.1109, 8.6821), 'Frankfurt', 'friends_only'),
    ('aaaaaaa2-aaaa-aaaa-aaaa-aaaaaaaaaaa2', '22222222-2222-2222-2222-222222222222', 'Mountain Hike', 'Solo hike in the mountains', '2023-07-10', ARRAY['hiking', 'mountains'], POINT(46.6193, 9.7124), 'Alps', 'nobody');

-- Inserting mock data into medias table
INSERT INTO medias (id, memory_id, type, url)
VALUES 
    ('bbbbbbb1-bbbb-bbbb-bbbb-bbbbbbbbbbb1', 'aaaaaaa1-aaaa-aaaa-aaaa-aaaaaaaaaaa1', 'image', 'http://example.com/images/beach1.jpg'),
    ('bbbbbbb2-bbbb-bbbb-bbbb-bbbbbbbbbbb2', 'aaaaaaa1-aaaa-aaaa-aaaa-aaaaaaaaaaa1', 'video', 'http://example.com/videos/beach1.mp4'),
    ('bbbbbbb3-bbbb-bbbb-bbbb-bbbbbbbbbbb3', 'aaaaaaa2-aaaa-aaaa-aaaa-aaaaaaaaaaa2', 'image', 'http://example.com/images/hike1.jpg');

-- Inserting mock data into comments table
INSERT INTO comments (id, memory_id, user_id, content)
VALUES 
    ('ccccccc1-cccc-cccc-cccc-ccccccccccc1', 'aaaaaaa1-aaaa-aaaa-aaaa-aaaaaaaaaaa1', '22222222-2222-2222-2222-222222222222', 'Looks fun!'),
    ('ccccccc2-cccc-cccc-cccc-ccccccccccc2', 'aaaaaaa2-aaaa-aaaa-aaaa-aaaaaaaaaaa2', '11111111-1111-1111-1111-111111111111', 'Amazing view!');

-- Inserting mock data into shared_memories table
INSERT INTO shared_memories (id, memory_id, shared_id, recipient_id, message)
VALUES 
    ('550e8400-e29b-41d4-a716-446655440000', 'aaaaaaa1-aaaa-aaaa-aaaa-aaaaaaaaaaa1', '11111111-1111-1111-1111-111111111111', '33333333-3333-3333-3333-333333333333', 'Check out our beach party!'),
    ('550e8400-e29b-41d4-a716-446655440001', 'aaaaaaa2-aaaa-aaaa-aaaa-aaaaaaaaaaa2', '22222222-2222-2222-2222-222222222222', '33333333-3333-3333-3333-333333333333', 'Here are some pics from my hike.');

-- Inserting mock data into custom_events table
INSERT INTO custom_events (id, user_id, title, description, date, category)
VALUES 
    ('eeeeeee1-eeee-eeee-eeee-eeeeeeeeeee1', '11111111-1111-1111-1111-111111111111', 'Graduation Party', 'Celebration for completing university', '2023-05-20', 'celebration'),
    ('eeeeeee2-eeee-eeee-eeee-eeeeeeeeeee2', '22222222-2222-2222-2222-222222222222', 'Company Annual Meeting', 'Annual meeting of the company employees', '2023-08-15', 'meeting');

-- Inserting mock data into milestones table
INSERT INTO milestones (id, user_id, title, date, category)
VALUES 
    ('fffffff1-ffff-ffff-ffff-fffffffffff1', '11111111-1111-1111-1111-111111111111', 'First Job', '2021-09-01', 'career'),
    ('fffffff2-ffff-ffff-ffff-fffffffffff2', '22222222-2222-2222-2222-222222222222', 'Bought a House', '2023-04-10', 'personal');
