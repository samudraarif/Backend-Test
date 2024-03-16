PGDMP  7                    |            tiketbioskop    16.2    16.2 W    e           0    0    ENCODING    ENCODING        SET client_encoding = 'UTF8';
                      false            f           0    0 
   STDSTRINGS 
   STDSTRINGS     (   SET standard_conforming_strings = 'on';
                      false            g           0    0 
   SEARCHPATH 
   SEARCHPATH     8   SELECT pg_catalog.set_config('search_path', '', false);
                      false            h           1262    16398    tiketbioskop    DATABASE     �   CREATE DATABASE tiketbioskop WITH TEMPLATE = template0 ENCODING = 'UTF8' LOCALE_PROVIDER = libc LOCALE = 'English_Indonesia.1252';
    DROP DATABASE tiketbioskop;
                postgres    false            �            1259    16539 
   audit_logs    TABLE     �   CREATE TABLE public.audit_logs (
    log_id integer NOT NULL,
    user_id integer,
    action character varying(50) NOT NULL,
    details text NOT NULL,
    "timestamp" timestamp without time zone DEFAULT (CURRENT_TIMESTAMP AT TIME ZONE 'UTC'::text)
);
    DROP TABLE public.audit_logs;
       public         heap    postgres    false            �            1259    16538    audit_logs_log_id_seq    SEQUENCE     �   CREATE SEQUENCE public.audit_logs_log_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
 ,   DROP SEQUENCE public.audit_logs_log_id_seq;
       public          postgres    false    234            i           0    0    audit_logs_log_id_seq    SEQUENCE OWNED BY     O   ALTER SEQUENCE public.audit_logs_log_id_seq OWNED BY public.audit_logs.log_id;
          public          postgres    false    233            �            1259    16426    cinemas    TABLE     p  CREATE TABLE public.cinemas (
    cinema_id integer NOT NULL,
    name character varying(255) NOT NULL,
    location text NOT NULL,
    number_of_screens integer NOT NULL,
    created_at timestamp without time zone DEFAULT (CURRENT_TIMESTAMP AT TIME ZONE 'UTC'::text),
    updated_at timestamp without time zone DEFAULT (CURRENT_TIMESTAMP AT TIME ZONE 'UTC'::text)
);
    DROP TABLE public.cinemas;
       public         heap    postgres    false            �            1259    16425    cinemas_cinema_id_seq    SEQUENCE     �   CREATE SEQUENCE public.cinemas_cinema_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
 ,   DROP SEQUENCE public.cinemas_cinema_id_seq;
       public          postgres    false    220            j           0    0    cinemas_cinema_id_seq    SEQUENCE OWNED BY     O   ALTER SEQUENCE public.cinemas_cinema_id_seq OWNED BY public.cinemas.cinema_id;
          public          postgres    false    219            �            1259    16415    movies    TABLE     �  CREATE TABLE public.movies (
    movie_id integer NOT NULL,
    title character varying(255) NOT NULL,
    duration integer NOT NULL,
    synopsis text,
    release_date date NOT NULL,
    genre character varying(50),
    created_at timestamp without time zone DEFAULT (CURRENT_TIMESTAMP AT TIME ZONE 'UTC'::text),
    updated_at timestamp without time zone DEFAULT (CURRENT_TIMESTAMP AT TIME ZONE 'UTC'::text)
);
    DROP TABLE public.movies;
       public         heap    postgres    false            �            1259    16414    movies_movie_id_seq    SEQUENCE     �   CREATE SEQUENCE public.movies_movie_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
 *   DROP SEQUENCE public.movies_movie_id_seq;
       public          postgres    false    218            k           0    0    movies_movie_id_seq    SEQUENCE OWNED BY     K   ALTER SEQUENCE public.movies_movie_id_seq OWNED BY public.movies.movie_id;
          public          postgres    false    217            �            1259    16524    payments    TABLE     �  CREATE TABLE public.payments (
    payment_id integer NOT NULL,
    reservation_id integer,
    amount numeric(10,2) NOT NULL,
    payment_method character varying(50) NOT NULL,
    status character varying(20) DEFAULT 'processing'::character varying,
    payment_time timestamp without time zone,
    created_at timestamp without time zone DEFAULT (CURRENT_TIMESTAMP AT TIME ZONE 'UTC'::text),
    updated_at timestamp without time zone DEFAULT (CURRENT_TIMESTAMP AT TIME ZONE 'UTC'::text)
);
    DROP TABLE public.payments;
       public         heap    postgres    false            �            1259    16523    payments_payment_id_seq    SEQUENCE     �   CREATE SEQUENCE public.payments_payment_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
 .   DROP SEQUENCE public.payments_payment_id_seq;
       public          postgres    false    232            l           0    0    payments_payment_id_seq    SEQUENCE OWNED BY     S   ALTER SEQUENCE public.payments_payment_id_seq OWNED BY public.payments.payment_id;
          public          postgres    false    231            �            1259    16485    reservations    TABLE     �  CREATE TABLE public.reservations (
    reservation_id integer NOT NULL,
    user_id integer,
    showtime_id integer,
    reservation_time timestamp without time zone NOT NULL,
    status character varying(20) DEFAULT 'pending'::character varying,
    created_at timestamp without time zone DEFAULT (CURRENT_TIMESTAMP AT TIME ZONE 'UTC'::text),
    updated_at timestamp without time zone DEFAULT (CURRENT_TIMESTAMP AT TIME ZONE 'UTC'::text)
);
     DROP TABLE public.reservations;
       public         heap    postgres    false            �            1259    16484    reservations_reservation_id_seq    SEQUENCE     �   CREATE SEQUENCE public.reservations_reservation_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
 6   DROP SEQUENCE public.reservations_reservation_id_seq;
       public          postgres    false    228            m           0    0    reservations_reservation_id_seq    SEQUENCE OWNED BY     c   ALTER SEQUENCE public.reservations_reservation_id_seq OWNED BY public.reservations.reservation_id;
          public          postgres    false    227            �            1259    16505    reserved_seats    TABLE     A  CREATE TABLE public.reserved_seats (
    reserved_seat_id integer NOT NULL,
    reservation_id integer,
    seat_id integer,
    created_at timestamp without time zone DEFAULT (CURRENT_TIMESTAMP AT TIME ZONE 'UTC'::text),
    updated_at timestamp without time zone DEFAULT (CURRENT_TIMESTAMP AT TIME ZONE 'UTC'::text)
);
 "   DROP TABLE public.reserved_seats;
       public         heap    postgres    false            �            1259    16504 #   reserved_seats_reserved_seat_id_seq    SEQUENCE     �   CREATE SEQUENCE public.reserved_seats_reserved_seat_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
 :   DROP SEQUENCE public.reserved_seats_reserved_seat_id_seq;
       public          postgres    false    230            n           0    0 #   reserved_seats_reserved_seat_id_seq    SEQUENCE OWNED BY     k   ALTER SEQUENCE public.reserved_seats_reserved_seat_id_seq OWNED BY public.reserved_seats.reserved_seat_id;
          public          postgres    false    229            �            1259    16437    screens    TABLE     _  CREATE TABLE public.screens (
    screen_id integer NOT NULL,
    cinema_id integer,
    screen_number integer NOT NULL,
    total_seats integer NOT NULL,
    created_at timestamp without time zone DEFAULT (CURRENT_TIMESTAMP AT TIME ZONE 'UTC'::text),
    updated_at timestamp without time zone DEFAULT (CURRENT_TIMESTAMP AT TIME ZONE 'UTC'::text)
);
    DROP TABLE public.screens;
       public         heap    postgres    false            �            1259    16436    screens_screen_id_seq    SEQUENCE     �   CREATE SEQUENCE public.screens_screen_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
 ,   DROP SEQUENCE public.screens_screen_id_seq;
       public          postgres    false    222            o           0    0    screens_screen_id_seq    SEQUENCE OWNED BY     O   ALTER SEQUENCE public.screens_screen_id_seq OWNED BY public.screens.screen_id;
          public          postgres    false    221            �            1259    16470    seats    TABLE     �  CREATE TABLE public.seats (
    seat_id integer NOT NULL,
    screen_id integer,
    "row" character(1) NOT NULL,
    number integer NOT NULL,
    status character varying(20) DEFAULT 'available'::character varying,
    created_at timestamp without time zone DEFAULT (CURRENT_TIMESTAMP AT TIME ZONE 'UTC'::text),
    updated_at timestamp without time zone DEFAULT (CURRENT_TIMESTAMP AT TIME ZONE 'UTC'::text)
);
    DROP TABLE public.seats;
       public         heap    postgres    false            �            1259    16469    seats_seat_id_seq    SEQUENCE     �   CREATE SEQUENCE public.seats_seat_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
 (   DROP SEQUENCE public.seats_seat_id_seq;
       public          postgres    false    226            p           0    0    seats_seat_id_seq    SEQUENCE OWNED BY     G   ALTER SEQUENCE public.seats_seat_id_seq OWNED BY public.seats.seat_id;
          public          postgres    false    225            �            1259    16451 	   showtimes    TABLE     y  CREATE TABLE public.showtimes (
    showtime_id integer NOT NULL,
    movie_id integer,
    screen_id integer,
    showtime time without time zone NOT NULL,
    date date NOT NULL,
    created_at timestamp without time zone DEFAULT (CURRENT_TIMESTAMP AT TIME ZONE 'UTC'::text),
    updated_at timestamp without time zone DEFAULT (CURRENT_TIMESTAMP AT TIME ZONE 'UTC'::text)
);
    DROP TABLE public.showtimes;
       public         heap    postgres    false            �            1259    16450    showtimes_showtime_id_seq    SEQUENCE     �   CREATE SEQUENCE public.showtimes_showtime_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
 0   DROP SEQUENCE public.showtimes_showtime_id_seq;
       public          postgres    false    224            q           0    0    showtimes_showtime_id_seq    SEQUENCE OWNED BY     W   ALTER SEQUENCE public.showtimes_showtime_id_seq OWNED BY public.showtimes.showtime_id;
          public          postgres    false    223            �            1259    16400    users    TABLE     �  CREATE TABLE public.users (
    user_id integer NOT NULL,
    username character varying(50) NOT NULL,
    email character varying(255) NOT NULL,
    password_hash character varying(255) NOT NULL,
    created_at timestamp without time zone DEFAULT (CURRENT_TIMESTAMP AT TIME ZONE 'UTC'::text),
    updated_at timestamp without time zone DEFAULT (CURRENT_TIMESTAMP AT TIME ZONE 'UTC'::text)
);
    DROP TABLE public.users;
       public         heap    postgres    false            �            1259    16399    users_user_id_seq    SEQUENCE     �   CREATE SEQUENCE public.users_user_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
 (   DROP SEQUENCE public.users_user_id_seq;
       public          postgres    false    216            r           0    0    users_user_id_seq    SEQUENCE OWNED BY     G   ALTER SEQUENCE public.users_user_id_seq OWNED BY public.users.user_id;
          public          postgres    false    215            �           2604    16542    audit_logs log_id    DEFAULT     v   ALTER TABLE ONLY public.audit_logs ALTER COLUMN log_id SET DEFAULT nextval('public.audit_logs_log_id_seq'::regclass);
 @   ALTER TABLE public.audit_logs ALTER COLUMN log_id DROP DEFAULT;
       public          postgres    false    234    233    234            �           2604    16429    cinemas cinema_id    DEFAULT     v   ALTER TABLE ONLY public.cinemas ALTER COLUMN cinema_id SET DEFAULT nextval('public.cinemas_cinema_id_seq'::regclass);
 @   ALTER TABLE public.cinemas ALTER COLUMN cinema_id DROP DEFAULT;
       public          postgres    false    219    220    220            �           2604    16418    movies movie_id    DEFAULT     r   ALTER TABLE ONLY public.movies ALTER COLUMN movie_id SET DEFAULT nextval('public.movies_movie_id_seq'::regclass);
 >   ALTER TABLE public.movies ALTER COLUMN movie_id DROP DEFAULT;
       public          postgres    false    218    217    218            �           2604    16527    payments payment_id    DEFAULT     z   ALTER TABLE ONLY public.payments ALTER COLUMN payment_id SET DEFAULT nextval('public.payments_payment_id_seq'::regclass);
 B   ALTER TABLE public.payments ALTER COLUMN payment_id DROP DEFAULT;
       public          postgres    false    232    231    232            �           2604    16488    reservations reservation_id    DEFAULT     �   ALTER TABLE ONLY public.reservations ALTER COLUMN reservation_id SET DEFAULT nextval('public.reservations_reservation_id_seq'::regclass);
 J   ALTER TABLE public.reservations ALTER COLUMN reservation_id DROP DEFAULT;
       public          postgres    false    227    228    228            �           2604    16508    reserved_seats reserved_seat_id    DEFAULT     �   ALTER TABLE ONLY public.reserved_seats ALTER COLUMN reserved_seat_id SET DEFAULT nextval('public.reserved_seats_reserved_seat_id_seq'::regclass);
 N   ALTER TABLE public.reserved_seats ALTER COLUMN reserved_seat_id DROP DEFAULT;
       public          postgres    false    229    230    230            �           2604    16440    screens screen_id    DEFAULT     v   ALTER TABLE ONLY public.screens ALTER COLUMN screen_id SET DEFAULT nextval('public.screens_screen_id_seq'::regclass);
 @   ALTER TABLE public.screens ALTER COLUMN screen_id DROP DEFAULT;
       public          postgres    false    222    221    222            �           2604    16473    seats seat_id    DEFAULT     n   ALTER TABLE ONLY public.seats ALTER COLUMN seat_id SET DEFAULT nextval('public.seats_seat_id_seq'::regclass);
 <   ALTER TABLE public.seats ALTER COLUMN seat_id DROP DEFAULT;
       public          postgres    false    225    226    226            �           2604    16454    showtimes showtime_id    DEFAULT     ~   ALTER TABLE ONLY public.showtimes ALTER COLUMN showtime_id SET DEFAULT nextval('public.showtimes_showtime_id_seq'::regclass);
 D   ALTER TABLE public.showtimes ALTER COLUMN showtime_id DROP DEFAULT;
       public          postgres    false    223    224    224            ~           2604    16403    users user_id    DEFAULT     n   ALTER TABLE ONLY public.users ALTER COLUMN user_id SET DEFAULT nextval('public.users_user_id_seq'::regclass);
 <   ALTER TABLE public.users ALTER COLUMN user_id DROP DEFAULT;
       public          postgres    false    216    215    216            b          0    16539 
   audit_logs 
   TABLE DATA           S   COPY public.audit_logs (log_id, user_id, action, details, "timestamp") FROM stdin;
    public          postgres    false    234   xo       T          0    16426    cinemas 
   TABLE DATA           g   COPY public.cinemas (cinema_id, name, location, number_of_screens, created_at, updated_at) FROM stdin;
    public          postgres    false    220   �o       R          0    16415    movies 
   TABLE DATA           r   COPY public.movies (movie_id, title, duration, synopsis, release_date, genre, created_at, updated_at) FROM stdin;
    public          postgres    false    218   �o       `          0    16524    payments 
   TABLE DATA           �   COPY public.payments (payment_id, reservation_id, amount, payment_method, status, payment_time, created_at, updated_at) FROM stdin;
    public          postgres    false    232   {p       \          0    16485    reservations 
   TABLE DATA           ~   COPY public.reservations (reservation_id, user_id, showtime_id, reservation_time, status, created_at, updated_at) FROM stdin;
    public          postgres    false    228   �p       ^          0    16505    reserved_seats 
   TABLE DATA           k   COPY public.reserved_seats (reserved_seat_id, reservation_id, seat_id, created_at, updated_at) FROM stdin;
    public          postgres    false    230   �p       V          0    16437    screens 
   TABLE DATA           k   COPY public.screens (screen_id, cinema_id, screen_number, total_seats, created_at, updated_at) FROM stdin;
    public          postgres    false    222   �p       Z          0    16470    seats 
   TABLE DATA           b   COPY public.seats (seat_id, screen_id, "row", number, status, created_at, updated_at) FROM stdin;
    public          postgres    false    226   bq       X          0    16451 	   showtimes 
   TABLE DATA           m   COPY public.showtimes (showtime_id, movie_id, screen_id, showtime, date, created_at, updated_at) FROM stdin;
    public          postgres    false    224   q       P          0    16400    users 
   TABLE DATA           `   COPY public.users (user_id, username, email, password_hash, created_at, updated_at) FROM stdin;
    public          postgres    false    216   �q       s           0    0    audit_logs_log_id_seq    SEQUENCE SET     D   SELECT pg_catalog.setval('public.audit_logs_log_id_seq', 1, false);
          public          postgres    false    233            t           0    0    cinemas_cinema_id_seq    SEQUENCE SET     C   SELECT pg_catalog.setval('public.cinemas_cinema_id_seq', 9, true);
          public          postgres    false    219            u           0    0    movies_movie_id_seq    SEQUENCE SET     B   SELECT pg_catalog.setval('public.movies_movie_id_seq', 10, true);
          public          postgres    false    217            v           0    0    payments_payment_id_seq    SEQUENCE SET     F   SELECT pg_catalog.setval('public.payments_payment_id_seq', 1, false);
          public          postgres    false    231            w           0    0    reservations_reservation_id_seq    SEQUENCE SET     N   SELECT pg_catalog.setval('public.reservations_reservation_id_seq', 1, false);
          public          postgres    false    227            x           0    0 #   reserved_seats_reserved_seat_id_seq    SEQUENCE SET     R   SELECT pg_catalog.setval('public.reserved_seats_reserved_seat_id_seq', 1, false);
          public          postgres    false    229            y           0    0    screens_screen_id_seq    SEQUENCE SET     D   SELECT pg_catalog.setval('public.screens_screen_id_seq', 24, true);
          public          postgres    false    221            z           0    0    seats_seat_id_seq    SEQUENCE SET     @   SELECT pg_catalog.setval('public.seats_seat_id_seq', 1, false);
          public          postgres    false    225            {           0    0    showtimes_showtime_id_seq    SEQUENCE SET     H   SELECT pg_catalog.setval('public.showtimes_showtime_id_seq', 14, true);
          public          postgres    false    223            |           0    0    users_user_id_seq    SEQUENCE SET     ?   SELECT pg_catalog.setval('public.users_user_id_seq', 3, true);
          public          postgres    false    215            �           2606    16547    audit_logs audit_logs_pkey 
   CONSTRAINT     \   ALTER TABLE ONLY public.audit_logs
    ADD CONSTRAINT audit_logs_pkey PRIMARY KEY (log_id);
 D   ALTER TABLE ONLY public.audit_logs DROP CONSTRAINT audit_logs_pkey;
       public            postgres    false    234            �           2606    16435    cinemas cinemas_pkey 
   CONSTRAINT     Y   ALTER TABLE ONLY public.cinemas
    ADD CONSTRAINT cinemas_pkey PRIMARY KEY (cinema_id);
 >   ALTER TABLE ONLY public.cinemas DROP CONSTRAINT cinemas_pkey;
       public            postgres    false    220            �           2606    16424    movies movies_pkey 
   CONSTRAINT     V   ALTER TABLE ONLY public.movies
    ADD CONSTRAINT movies_pkey PRIMARY KEY (movie_id);
 <   ALTER TABLE ONLY public.movies DROP CONSTRAINT movies_pkey;
       public            postgres    false    218            �           2606    16532    payments payments_pkey 
   CONSTRAINT     \   ALTER TABLE ONLY public.payments
    ADD CONSTRAINT payments_pkey PRIMARY KEY (payment_id);
 @   ALTER TABLE ONLY public.payments DROP CONSTRAINT payments_pkey;
       public            postgres    false    232            �           2606    16493    reservations reservations_pkey 
   CONSTRAINT     h   ALTER TABLE ONLY public.reservations
    ADD CONSTRAINT reservations_pkey PRIMARY KEY (reservation_id);
 H   ALTER TABLE ONLY public.reservations DROP CONSTRAINT reservations_pkey;
       public            postgres    false    228            �           2606    16512 "   reserved_seats reserved_seats_pkey 
   CONSTRAINT     n   ALTER TABLE ONLY public.reserved_seats
    ADD CONSTRAINT reserved_seats_pkey PRIMARY KEY (reserved_seat_id);
 L   ALTER TABLE ONLY public.reserved_seats DROP CONSTRAINT reserved_seats_pkey;
       public            postgres    false    230            �           2606    16444    screens screens_pkey 
   CONSTRAINT     Y   ALTER TABLE ONLY public.screens
    ADD CONSTRAINT screens_pkey PRIMARY KEY (screen_id);
 >   ALTER TABLE ONLY public.screens DROP CONSTRAINT screens_pkey;
       public            postgres    false    222            �           2606    16478    seats seats_pkey 
   CONSTRAINT     S   ALTER TABLE ONLY public.seats
    ADD CONSTRAINT seats_pkey PRIMARY KEY (seat_id);
 :   ALTER TABLE ONLY public.seats DROP CONSTRAINT seats_pkey;
       public            postgres    false    226            �           2606    16458    showtimes showtimes_pkey 
   CONSTRAINT     _   ALTER TABLE ONLY public.showtimes
    ADD CONSTRAINT showtimes_pkey PRIMARY KEY (showtime_id);
 B   ALTER TABLE ONLY public.showtimes DROP CONSTRAINT showtimes_pkey;
       public            postgres    false    224            �           2606    16413    users users_email_key 
   CONSTRAINT     Q   ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_email_key UNIQUE (email);
 ?   ALTER TABLE ONLY public.users DROP CONSTRAINT users_email_key;
       public            postgres    false    216            �           2606    16409    users users_pkey 
   CONSTRAINT     S   ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_pkey PRIMARY KEY (user_id);
 :   ALTER TABLE ONLY public.users DROP CONSTRAINT users_pkey;
       public            postgres    false    216            �           2606    16411    users users_username_key 
   CONSTRAINT     W   ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_username_key UNIQUE (username);
 B   ALTER TABLE ONLY public.users DROP CONSTRAINT users_username_key;
       public            postgres    false    216            �           2606    16548 "   audit_logs audit_logs_user_id_fkey    FK CONSTRAINT     �   ALTER TABLE ONLY public.audit_logs
    ADD CONSTRAINT audit_logs_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(user_id);
 L   ALTER TABLE ONLY public.audit_logs DROP CONSTRAINT audit_logs_user_id_fkey;
       public          postgres    false    234    216    4769            �           2606    16533 %   payments payments_reservation_id_fkey    FK CONSTRAINT     �   ALTER TABLE ONLY public.payments
    ADD CONSTRAINT payments_reservation_id_fkey FOREIGN KEY (reservation_id) REFERENCES public.reservations(reservation_id);
 O   ALTER TABLE ONLY public.payments DROP CONSTRAINT payments_reservation_id_fkey;
       public          postgres    false    228    232    4783            �           2606    16499 *   reservations reservations_showtime_id_fkey    FK CONSTRAINT     �   ALTER TABLE ONLY public.reservations
    ADD CONSTRAINT reservations_showtime_id_fkey FOREIGN KEY (showtime_id) REFERENCES public.showtimes(showtime_id);
 T   ALTER TABLE ONLY public.reservations DROP CONSTRAINT reservations_showtime_id_fkey;
       public          postgres    false    4779    228    224            �           2606    16494 &   reservations reservations_user_id_fkey    FK CONSTRAINT     �   ALTER TABLE ONLY public.reservations
    ADD CONSTRAINT reservations_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(user_id);
 P   ALTER TABLE ONLY public.reservations DROP CONSTRAINT reservations_user_id_fkey;
       public          postgres    false    216    228    4769            �           2606    16513 1   reserved_seats reserved_seats_reservation_id_fkey    FK CONSTRAINT     �   ALTER TABLE ONLY public.reserved_seats
    ADD CONSTRAINT reserved_seats_reservation_id_fkey FOREIGN KEY (reservation_id) REFERENCES public.reservations(reservation_id);
 [   ALTER TABLE ONLY public.reserved_seats DROP CONSTRAINT reserved_seats_reservation_id_fkey;
       public          postgres    false    4783    230    228            �           2606    16518 *   reserved_seats reserved_seats_seat_id_fkey    FK CONSTRAINT     �   ALTER TABLE ONLY public.reserved_seats
    ADD CONSTRAINT reserved_seats_seat_id_fkey FOREIGN KEY (seat_id) REFERENCES public.seats(seat_id);
 T   ALTER TABLE ONLY public.reserved_seats DROP CONSTRAINT reserved_seats_seat_id_fkey;
       public          postgres    false    226    230    4781            �           2606    16445    screens screens_cinema_id_fkey    FK CONSTRAINT     �   ALTER TABLE ONLY public.screens
    ADD CONSTRAINT screens_cinema_id_fkey FOREIGN KEY (cinema_id) REFERENCES public.cinemas(cinema_id);
 H   ALTER TABLE ONLY public.screens DROP CONSTRAINT screens_cinema_id_fkey;
       public          postgres    false    220    4775    222            �           2606    16479    seats seats_screen_id_fkey    FK CONSTRAINT     �   ALTER TABLE ONLY public.seats
    ADD CONSTRAINT seats_screen_id_fkey FOREIGN KEY (screen_id) REFERENCES public.screens(screen_id);
 D   ALTER TABLE ONLY public.seats DROP CONSTRAINT seats_screen_id_fkey;
       public          postgres    false    222    4777    226            �           2606    16459 !   showtimes showtimes_movie_id_fkey    FK CONSTRAINT     �   ALTER TABLE ONLY public.showtimes
    ADD CONSTRAINT showtimes_movie_id_fkey FOREIGN KEY (movie_id) REFERENCES public.movies(movie_id);
 K   ALTER TABLE ONLY public.showtimes DROP CONSTRAINT showtimes_movie_id_fkey;
       public          postgres    false    4773    218    224            �           2606    16464 "   showtimes showtimes_screen_id_fkey    FK CONSTRAINT     �   ALTER TABLE ONLY public.showtimes
    ADD CONSTRAINT showtimes_screen_id_fkey FOREIGN KEY (screen_id) REFERENCES public.screens(screen_id);
 L   ALTER TABLE ONLY public.showtimes DROP CONSTRAINT showtimes_screen_id_fkey;
       public          postgres    false    224    222    4777            #           826    16554    DEFAULT PRIVILEGES FOR TABLES    DEFAULT ACL     I   ALTER DEFAULT PRIVILEGES FOR ROLE postgres GRANT ALL ON TABLES TO admin;
                   postgres    false            b      x������ � �      T   V   x�3�t��K�MT0���ON,���2�9��Lt�u�,�LL���,���p�pY��2B�TO�Y�0��fs��eV� �q2Y      R   p   x�3�t���Up�442����4202�50"N����<������������������������1).c��N��HƂL�t��MM�$�X��Μ��H���u)J�M$��=... "�6n      `      x������ � �      \      x������ � �      ^      x������ � �      V   �   x�����0�P�6��1�S��_�f ���f�1Z�$ )�/�%���}���P+&���k��CB�5y���ð��e�=�Nz�)
昰�]L�\����x-
bh��?/�Z�:�w0�*���      Z      x������ � �      X   p   x���Q
1���^�%3�u��x�s��.
*B>
��(!p�L����Ќ�ͼa\l����a~��0

��O�B�c��1�����7&��|?v�v���"����U�^�<}      P   �   x�3�LL����,I-.qH�M���K���T1JT14R1�,�2t��*LIsML�+.��,L�33�t��u�qq��+1(�L1�H�4202�50�54S0��24"=CK�2\�w�b8�.����� Y J�     