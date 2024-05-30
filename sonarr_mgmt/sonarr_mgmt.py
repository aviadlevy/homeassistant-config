#!/usr/bin/env python3
import pickle
import sys
import time
from datetime import datetime, timedelta
from threading import Condition
import urllib.parse

import requests
import logging
from trakt import Trakt

from secrets import *

is_authenticating = Condition()
global my_auth
my_auth = None

Trakt.base_url = "http://api.trakt.tv"
Trakt.configuration.defaults.http(retry=True)
Trakt.configuration.defaults.oauth(refresh=True)
Trakt.configuration.defaults.client(
    id=trakt_client_id,
    secret=trakt_client_service
)

logger = logging.getLogger()
logger.setLevel(logging.INFO)
ch = logging.StreamHandler()
ch.setLevel(logging.INFO)
formatter = logging.Formatter("%(asctime)s;%(levelname)s;%(message)s",
                              "%Y-%m-%d %H:%M:%S")
ch.setFormatter(formatter)
logger.addHandler(ch)


def log(msg):
    logger.info(msg)


class WatchedMonitor(object):

    def __init__(self):
        global my_auth
        # Bind trakt events
        Trakt.on("oauth.token_refreshed", self.on_token_refreshed)
        # Try to read auth from file
        my_auth = self.auth_load()
        # If not read from file, get new auth and save to file
        if not my_auth:
            self.authenticate()
        if not my_auth:
            log("ERROR: Authentication required")
            exit(1)

    def auth_load(self):
        try:
            with open(auth_pkl_path, "rb") as f:
                auth_file = pickle.load(f)
            return auth_file
        except:
            pass

    def authenticate(self):
        if not is_authenticating.acquire(blocking=False):
            log("Authentication has already been started")
            return False

        # Request new device code
        code = Trakt["oauth/device"].code()

        log("Enter the code \"%s\" at %s to authenticate your account" % (
            code.get("user_code"),
            code.get("verification_url")
        ))

        # Construct device authentication poller
        poller = Trakt["oauth/device"].poll(**code) \
            .on("aborted", self.on_aborted) \
            .on("authenticated", self.on_authenticated) \
            .on("expired", self.on_expired) \
            .on("poll", self.on_poll)

        # Start polling for authentication token
        poller.start(daemon=False)

        # Wait for authentication to complete
        return is_authenticating.wait()

    def trakt_get_episodes(self, recent_days):
        with Trakt.configuration.oauth.from_response(my_auth, refresh=True):
            # Expired token will be refreshed automatically (as `refresh=True`)
            today = datetime.now()
            recent_date = today - timedelta(days=recent_days)
            show_episodes = dict()

            log(" Trakt: Episodes watched in last " + str(recent_days) + " days:")
            for episode in Trakt["sync/history"].shows(start_at=recent_date, pagination=True, extended="full"):
                episode_dict = episode.to_dict()
                ep_no = episode_dict["number"]
                show = episode.show
                season = episode.season
                season_no = season.pk
                show_tvdb = show.pk[1]

                if show_tvdb in show_episodes:
                    # show_episodes_tvdbids[show_tvdb].append(episode_dict["ids"]["tvdb"])
                    show_episodes[show_tvdb].append([season_no, ep_no])
                else:
                    show_episodes[show_tvdb] = []
                    show_episodes[show_tvdb].append([season_no, ep_no])

                log("  " + show.title + " - S" + str(season_no).zfill(2) + "E" + str(episode_dict["number"]).zfill(
                    2) + ": " + episode_dict["title"])

        return show_episodes

    def sonarr(self):

        log("TV:")
        show_episodes = self.trakt_get_episodes(recent_days)

        log("")
        log(" Sonarr:")

        # Get all series from sonarr
        response = requests.get("http://" + sonarr_address + "/api/v3/series?apikey=" + sonarr_apikey)

        if response.status_code == 401:
            sys.exit("ERROR: Unauthorized request to Sonarr API. Are you sure the API key is correct?")

        # Look for recently watched episodes in Sonarr and change monitored to False
        log("\n  Episodes found and changed in Sonarr:")
        series = response.json()
        for showid_string in show_episodes:
            showid = int(showid_string)

            for show in series:
                try:
                    sonarr_tvdb = show["tvdbId"]
                    sonarr_id = show["id"]
                except:
                    sonarr_tvdb = 0

                if showid == sonarr_tvdb:
                    log("   " + show["title"])

                    # Get all episodes in show from Sonarr
                    response_eps = requests.get("http://" + sonarr_address + "/api/v3/episode/?seriesID=" + str(
                        sonarr_id) + "&apikey=" + sonarr_apikey)
                    sonarr_show_eps = response_eps.json()

                    for trakt_season_ep in show_episodes[showid_string]:
                        trakt_season = trakt_season_ep[0]
                        trakt_ep = trakt_season_ep[1]

                        for sonarr_show_ep in sonarr_show_eps:
                            try:
                                sonarr_ep = sonarr_show_ep["episodeNumber"]
                                sonarr_season = sonarr_show_ep["seasonNumber"]
                                sonarr_epid = sonarr_show_ep["id"]
                            except:
                                sonarr_ep = 0
                                sonarr_season = 0

                            if trakt_season == sonarr_season and trakt_ep == sonarr_ep:
                                log("    - S" + str(sonarr_season).zfill(2) + "E" + str(sonarr_ep).zfill(2))

                                # Get sonarr episode
                                request_uri = "http://" + sonarr_address + "/api/v3/episode/" + str(
                                    sonarr_epid) + "?apikey=" + sonarr_apikey
                                sonarr_episode_json = requests.get(request_uri).json()

                                if sonarr_delete_file:
                                    if "episodeFile" not in sonarr_episode_json.keys():
                                        log("      You wanted to delete this episode but it doesn't exists")
                                    else:
                                        log("      Trying to delete episode")
                                        sonarr_episodefile_id = sonarr_episode_json["episodeFile"]["id"]
                                        request_uri = "http://" + sonarr_address + "/api/v3/episodefile/" + str(
                                            sonarr_episodefile_id) + "?apikey=" + sonarr_apikey
                                        r = requests.delete(request_uri)
                                        if r.status_code != 200:
                                            log("   Error: " + str(r.text))

                                    try:
                                        # Get sonarr episode subtitle if exists
                                        request_uri = f"http://{bazarr_address}/api/episodes?episodeid%5B%5D=" + str(
                                            sonarr_epid)
                                        bazarr_episode_json = requests.get(request_uri, headers={
                                            'accept': 'application/json',
                                            'X-API-KEY': bazarr_apikey
                                        }).json()

                                        if len(bazarr_episode_json.get("data", [])) > 0 and len(
                                                bazarr_episode_json["data"][0].get("subtitles", [])) > 0:
                                            for sub in bazarr_episode_json["data"][0]["subtitles"]:
                                                if sub.get("path"):
                                                    log("      Trying to delete subtitle as well")
                                                    code2 = sub.get("code2")
                                                    forced = sub.get("forced")
                                                    hi = sub.get("hi")
                                                    path = urllib.parse.quote_plus(sub.get("path"))
                                                    request_uri = f'http://{bazarr_address}/api/episodes/subtitles?seriesid={sonarr_id}&episodeid={sonarr_epid}&language={code2}&forced={forced}&hi={hi}&path={path}'
                                                    r = requests.delete(request_uri, headers={
                                                        'accept': 'application/json',
                                                        'X-API-KEY': bazarr_apikey
                                                    })
                                                    if r.status_code != 200 or r.status_code != 204:
                                                        log("   Error: " + str(r.text))
                                    except Exception as e:
                                        log(f"Error: {repr(e)}")

    def on_aborted(self):
        """Device authentication aborted.

        Triggered when device authentication was aborted (either with `DeviceOAuthPoller.stop()`
        or via the "poll" event)
        """

        log("Authentication aborted")
        is_authenticating.acquire()
        is_authenticating.notify_all()
        is_authenticating.release()

    def on_authenticated(self, authorization):
        """Device authenticated.

        :param authorization: Authentication token details
        :type authorization: dict
        """
        global my_auth
        # Acquire condition
        is_authenticating.acquire()

        # Store authorization for future calls
        my_auth = authorization

        # Save authorization to file
        with open(auth_pkl_path, "wb") as f:
            pickle.dump(authorization, f, pickle.HIGHEST_PROTOCOL)
            log("saved pkl to /app/creds/auth.pkl")

        log("Authentication successful - authorization: %r" % authorization)
        log("")
        log("")

        # Authentication complete
        is_authenticating.notify_all()
        is_authenticating.release()

    def on_expired(self):
        """Device authentication expired."""

        log("Authentication expired")

        # Authentication expired
        is_authenticating.acquire()
        is_authenticating.notify_all()
        is_authenticating.release()

    def on_poll(self, callback):
        """Device authentication poll.

        :param callback: Call with `True` to continue polling, or `False` to abort polling
        :type callback: func
        """

        # Continue polling
        callback(True)

    def on_token_refreshed(self, authorization):
        global my_auth
        # OAuth token refreshed, store authorization for future calls
        my_auth = authorization

        log("Token refreshed - authorization: %r" % authorization)


if __name__ == '__main__':
    watchmon = WatchedMonitor()
    while True:
        log("starting...")
        watchmon.sonarr()
        log("sleeping for 6 hours")
        time.sleep(60 * 60 * 6)

