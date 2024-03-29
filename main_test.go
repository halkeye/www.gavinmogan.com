package main

import (
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

var urlsFromSitemap = `
/presentations/jenkins-world-2017-gavinmogan-saucelabs/
/presentations/codecoffee-no-rest-for-the-wicked/
/presentations/codecoffee-why-not-testing/
/presentations/codecoffee-vagrant/
/presentations/react-vs-angular/
/presentations/stats/
/presentations/linux101/
/presentations/devops/
/presentations/vim/
/projects/radiant-joanna/
/projects/soundboard/
/projects/MTLJPost/
/projects/flask-atlassian-connect/
/projects/ecm/
/projects/dark-warriors/
/projects/hipchat-dance-party/
/projects/ingrid-intimidator/
/projects/infinicatr/
/projects/jira-cloud-and-bamboohr-integration/
/projects/kode_foto_backup/
/projects/npm-modules/
/projects/salty-stories-web/
/projects/unknown-regions/
/projects/zabox/
/
/2
/3
/4
/5
/6
/7
/8
/9
/10
/11
/12
/13
/14
/15
/16
/17
/18
/19
/20
/21
/22
/23
/24
/25
/26
/27
/2020/04/20/docker-registry-g4v-dev
/2020/01/03/winter-diorama-christmas-present
/2019/12/01/backup-helm-openldap-data
/2019/10/10/new-tabletop-rpg-tokens
/2018/08/16/open-source-and-me
/2018/05/16/NodeSchool-NodeBots
/2018/05/15/new-website
/2018/04/07/export-dropbox-to-disk
/2018/02/04/docker-pi-hole-dnssec-dnscrypt
/2018/01/27/dockerizing-services
/2017/09/25/jenkins-world-2017-interview
/2017/07/29/new-position-open-source-and-more
/2017/02/12/systemd-tshock-docker
/2016/11/06/high-school-robotics-compeition
/2016/11/03/cat-plays-with-new-cat-toy-box
/2016/10/26/sauce-labs-hipchat-service-and-open-source
/2016/10/06/gavin-mental-health
/2016/09/20/test-allthethings-at-jenkins-world-2016
/2016/09/20/my-second-fringe-show-how-to-adult
/2016/09/16/grounded
/2016/09/05/projects
/2016/05/14/my-gopro-experiments
/2016/05/13/talk-on-testing
/2016/04/18/jenkins-docker-image-prefix
/2016/04/17/bbq-chicken-pizza
/2016/02/15/bad-twitter-joke
/2016/02/15/i-keep-losing-this-tweet
/2016/02/08/telltales-back-to-the-future
/2016/01/16/media-im-really-enjoying
/2016/01/09/meatballs
/2016/01/06/cat-2
/2016/01/02/secret-loves-geek-girls
/2015/07/03/587
/2015/03/31/nginx-cloudflare-ssl
/2015/01/26/gming
/2014/08/24/local-indie-production
/2014/06/06/update-capistrano-hack
/2014/04/12/direnv-coolest-tools
/2014/03/19/bash-prompt-linewrap-colors-issues
/2014/02/01/feb-1st-2014-unique-milestone
/2014/01/24/capistrano3-deploying-internal-git-server
/2013/12/31/yaoirpg
/2013/12/31/2013-review
/2013/09/28/renaming-batch-files-spaces-linux
/2013/08/20/updating-wordpress-plugins-helper
/2013/03/09/android-snes
/2012/07/16/change-mateterminal-xfce4terminal
/2012/04/06/busy-week
/2012/03/14/output-pretty-json-puppet
/2012/02/17/gitpush-notification-gitolite-andjenkins
/2012/02/08/historical-livejournal
/2011/09/13/terraria
/2010/10/20/lacuna-expanse
/2010/08/22/dragon-quest-ix-completion-stats
/2010/07/09/debugging-sshsvn
/2010/06/18/open-id-travels-rewards
/2010/02/12/batman
/2010/01/20/free-laptop-facebook-scam
/2009/10/07/1007i_get_my_own_ugly_code
/2008/05/19/osqdb_has_be_one_worst_peices_code_i_have_seen_while
/2008/05/04/finished_naruto_rise_ninja
/2008/05/04/outside_free_comic_book_day_elfsar
/2008/04/04/please_people_learn_ask_questions
/2008/03/29/snow_skytrain
/2008/01/06/xbox_live_cards
/2007/12/03/tin_man
/2007/09/29/stargate_atlantis_and_more
/2007/09/06/stats_tracking
/2007/09/05/hi_scifi_sources
/2007/04/28/drive_gets_canceled
/2007/04/01/halkeye_net
/2007/03/31/i_think_i_found_client_i_love
/2007/03/31/cjsf_changed_thier_schema_again
/2007/03/21/telemarketers
/2007/03/11/demos
/2007/03/06/new_book_all_my_friends_are_superheroes
/2007/02/14/epic_movie
/2007/02/12/futureshop_woes
/2007/02/11/superman_such_peeping_tom
/2007/01/20/bash_org
/2007/01/14/upgrade_galore
/2006/11/04/awesome_new_firefox_2_0_plugin
/2006/11/02/picture_21_jpg
/2006/10/17/y_o_i_r_p_g
/2006/10/16/wow_ecto_impressive
/2006/06/17/quake_4_has_zombies
/2006/06/03/new_site_and_running
/2006/06/03/nostalgic
/2006/04/10/nuvexport
/2006/03/12/post_secret_love
/2006/03/11/any_issues
/2006/02/25/babylon_5
/2006/02/18/utter_crap
/2006/02/18/cjsfs_archive
/2006/02/18/new_apache
/2006/02/13/eternitys_end
/2006/02/12/gforge_woes_and_praise
/2006/01/17/yay
/2005/12/11/apache_dso
/2005/11/22/scott_adams_genius
/2005/10/23/more_jabber_ideas
/2005/10/21/testing_posting_flock
/2005/10/10/s_r_i_p_s_okrut
/2005/10/02/new_mtljpost_version
/2005/10/02/oblivion_video
/2005/09/27/life_updates
/2005/09/27/im_so_much_love_google_video
/2005/09/15/hookers_r_us
/2005/09/12/bearcave_fun
/2005/09/02/spam_protection
/2005/08/06/lightsaber_thoughts
/2005/08/01/got_password_resetters_working
/2005/07/30/x_forwarding_just_rocks
/2005/07/30/podcasting_ho
/2005/07/29/new_design_and_new_software
/2005/07/25/possible_upgrade
/2005/06/19/fear_closed_mp_beta
/2005/06/10/does_music_have_soul
/2005/06/08/im_not_sadisitic_just_robbed
/2005/05/28/still_around
/2005/05/06/featuring_website
/2005/04/26/okay_back_sorta
/2005/04/12/playing_my_new_camera
/2005/04/02/knights_temple_infernal_crusade
/2005/03/30/typekey
/2005/03/29/experience_okcupid_efnet
/2005/03/21/starting_final_cut
/2005/03/17/thunderbird_vs_evolution
/2005/03/14/kode_kode_coding
/2005/03/14/robin_williams
/2005/03/13/lego_starwars_0
/2005/03/13/macross_plus
/2005/02/21/website_design
/2005/02/20/nikitia
/2005/02/15/more_stargate_wows
/2005/02/11/stargate_sg_1
/2005/02/09/dovecot_and_squirrelmail
/2005/02/09/site_updates
/2005/02/09/man_its_been_while
/2005/01/02/merry_christmas
/2004/12/16/meow
/2004/09/03/i_still_live
/2004/07/20/firefox_shortcut_domain_names
/2004/07/20/firefox_shortcuts_cpan_must_have_any_perl_programmer
/2004/06/24/halkpost
/2004/06/24/love_tidy
/2004/06/16/stupid_people_shouldnt_be_allowed_go_online
/2004/05/22/yet_another_test_post
/2004/05/07/may_fun_month
/2004/05/05/spears
/2004/05/01/stargate_atlantis
/2004/05/01/got_kingdom_hearts
/2004/05/01/blogger
/2004/04/30/dating
/2004/04/29/apparenly_im_widely_known
/2004/04/28/sorry
/2004/04/27/vancouver_way_life
/2004/04/25/strange_urge
/2004/04/24/ahh_scam_beware
/2004/04/18/iriver_hp_120
/2004/04/17/work
/2004/04/16/2_6_x
/2004/04/15/pick_pocketing
/2004/04/14/why_perl_people_rule
/2004/04/13/catch_phrases
/2004/04/13/apache_modifications
/2004/04/12/pick_lines
/2004/04/12/xbox_server_farm
/2004/04/12/lazy_morning
/2004/04/10/its_emails_make_it_all_worth_it
/2004/04/10/stargate
/2004/04/07/tron
/2004/04/06/hoobastank
/2004/04/04/mtljpost_1_6_now_1_7_1
/2004/04/04/movie_prices
/2004/04/04/dawn_dead
/2004/04/02/test
/2004/03/28/mod_perl
/2004/03/25/interesting_idea
/2004/03/24/comedy_while_half_asleep
/2004/03/23/amazon_com
/2004/03/12/speaker_dead_more
/2004/03/11/speaker_dead
/2004/03/09/whats_difference
/2004/03/03/boooks
/2004/02/29/gay_marrages
/2004/02/29/sucky_story_teller_interesting_stories
/2004/02/24/yay_used_books
/2004/02/24/laser_tag
/2004/02/22/enders_game
/2004/02/20/why
/2004/02/18/bcits_ad
/2004/02/18/deep_space_nine
/2004/02/18/bugs_bunny
/2004/02/17/oceans_11
/2004/02/16/episode_16
/2004/02/16/teamspeak
/2004/02/15/stating_obvious
/2004/02/14/ut2004
/2004/02/14/bah_celebration_st_valentines
/2004/02/12/no_purchase_necessary
/2004/02/12/vancouver
/2004/02/11/good_golly_miss_molly
/2004/02/10/legend_green_dragon
/2004/02/09/mtljpost_1_0_5_released
/2004/02/09/animal_crossing_and_ideal_house
/2004/02/08/mp3_cd_player_rant
/2004/02/05/broken_sword_3
/2004/02/05/maaaaaa
/2004/02/05/preview_mtljpost_1_0_5
/2004/02/04/one_must_fall_battlegrounds
/2004/02/02/mt_blacklist
/2004/02/01/slightly_new_color_scheme
/2004/01/30/ininja
/2004/01/30/mtljpost_1_0_3_released
/2004/01/30/haha_another_new_version
/2004/01/30/mtljpost_new_version
/2004/01/29/syndication
/2004/01/29/mtljpost
/2004/01/24/gui_design
/2004/01/22/ewww_perl_semantics
/2004/01/20/mailserver_update_update
/2004/01/20/sucks_be_me
/2004/01/18/mtljtag
/2004/01/18/clone_high
/2004/01/18/server_upgrade
/2004/01/09/php_meetup
/2004/01/02/im_baccck_and_upgraded
/2003/12/01/wish_i_had_caller_id_then_id_be_cool
/2003/11/17/motd
/2003/11/11/site_updates_dont_forget_about_stacys_mom_cause_she_has_it_going
/2003/10/30/jedi_academy
/2003/10/29/xargs_fun
/2003/10/18/emails
/2003/10/18/renewed_interest_dating
/2003/10/15/new_mirc_fixes_bugs
/2003/10/11/klingon
/2003/10/09/us_going_canadian
/2003/10/08/crushes_does_not_belong_posts
/2003/10/08/time_travel_s_crushes_s
/2003/10/01/wheee_mrtg
/2003/10/01/trying_post_more_things
/2003/09/20/multi_theft_auto
/2003/09/08/mail_server_upgrades
/2003/09/07/gavin_got_game
/2003/08/13/the_story_of_th
/2003/08/12/devilman_lady_r
/2003/08/06/piracy
/2003/08/02/mirc_scripts_sn
/2003/08/01/girlfriends_wel
/2003/07/29/con_not_report
/2003/07/21/gentoo
/2003/07/20/good_news_bad_n
/2003/07/19/email_love
/2003/07/17/knights_of_the_1
/2003/07/14/my_k-pax_review
/2003/07/10/i_got_a_produce
/2003/06/29/it_seems_im_all
/2003/06/27/drew_carry_show
/2003/06/27/software_and_si
/2003/06/20/harry_potter_nu
/2003/06/17/damn_this_condi
/2003/06/16/rockport_pd
/2003/06/14/site_update
/2003/06/11/trillian_pro_mi
/2003/06/09/my_ever_so_lame
/2003/06/07/been_trying_out
/2003/06/06/wheee
/2003/04/17/first_post
/about/
/computers/
/presentations/
/projects/
`

// /1 is just a page on the blog, we can ignore it for now
var pageRegex = regexp.MustCompile("^/\\d+$")

func TestSitemap(t *testing.T) {
	mux := http.NewServeMux()
	setupRoutes(mux)

	for _, tc := range strings.Split(urlsFromSitemap, "\n") {
		if len(tc) == 0 {
			continue
		}
		if pageRegex.MatchString(tc) {
			continue
		}
		t.Run("Make sure "+tc+" Redirects", func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, tc, nil)
			resp := httptest.NewRecorder()

			mux.ServeHTTP(resp, request)

			statusCode := resp.Result().StatusCode
			if statusCode != 200 && statusCode != 301 {
				t.Fatalf("the status code should be 200 or 301 but received [%d]", statusCode)
			}

			if statusCode == 301 {
				req, err := http.NewRequest(http.MethodGet, resp.Result().Header.Get("Location"), nil)
				require.NoError(t, err, "creating request")

				res, err := http.DefaultClient.Do(req)
				require.NoError(t, err, "creating request")

				require.Equal(t, res.StatusCode, 200, "Ends in valid locaiton")
			}
		})
	}
}
